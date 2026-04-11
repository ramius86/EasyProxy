import logging
import random
import re
import time
import string
from urllib.parse import urlparse
from aiohttp import ClientSession, ClientTimeout, TCPConnector
from aiohttp_socks import ProxyConnector
from playwright.async_api import async_playwright

logger = logging.getLogger(__name__)

class ExtractorError(Exception):
    pass

class DoodStreamExtractor:
    """DoodStream URL extractor."""

    def __init__(
        self,
        request_headers: dict,
        proxies: list = None,
    ):
        self.request_headers = request_headers
        self.base_headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        self.session = None
        self.mediaflow_endpoint = "proxy_stream_endpoint"
        self.proxies = proxies or []
        self.base_url = "https://d000d.com"

    def _get_random_proxy(self):
        return random.choice(self.proxies) if self.proxies else None

    @staticmethod
    def _random_suffix(length: int = 10) -> str:
        alphabet = string.ascii_letters + string.digits
        return "".join(random.choice(alphabet) for _ in range(length))

    @staticmethod
    def _extract_pass_and_token(text: str) -> tuple[str | None, str | None]:
        pass_match = re.search(r"(/pass_md5/[^\"'\s]+)", text)
        token_match = re.search(r"\?token=([^\"'&\s]+)&expiry=", text)
        pass_path = pass_match.group(1) if pass_match else None
        token = token_match.group(1) if token_match else None

        if not token and pass_path:
            path_parts = [part for part in pass_path.split("/") if part]
            if len(path_parts) >= 2 and path_parts[0] == "pass_md5":
                token = path_parts[-1]

        return pass_path, token

    async def _fetch_player_data_via_browser(
        self, url: str
    ) -> tuple[str | None, str | None, str | None, str, str]:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                headless=True,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--autoplay-policy=no-user-gesture-required",
                    "--disable-dev-shm-usage",
                ],
            )
            context = await browser.new_context(
                user_agent=self.base_headers["user-agent"],
                locale="en-US",
                viewport={"width": 1366, "height": 768},
            )
            await context.add_init_script(
                """
                Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
                Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
                Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4] });
                window.chrome = window.chrome || { runtime: {} };
                """
            )
            page = await context.new_page()
            pass_path: str | None = None
            token: str | None = None
            pass_body: str | None = None

            async def handle_response(response):
                nonlocal pass_path, token, pass_body
                response_url = response.url
                if "/pass_md5/" not in response_url:
                    return
                if not pass_path:
                    parsed = urlparse(response_url)
                    pass_path = parsed.path
                if not token:
                    token_match = re.search(r"[?&]token=([^&]+)", response_url)
                    if token_match:
                        token = token_match.group(1)
                if not token and pass_path:
                    path_parts = [part for part in pass_path.split("/") if part]
                    if len(path_parts) >= 2 and path_parts[0] == "pass_md5":
                        token = path_parts[-1]
                if pass_body is None:
                    try:
                        pass_body = await response.text()
                    except Exception:
                        pass

            page.on("response", handle_response)
            await page.goto(url, wait_until="domcontentloaded", timeout=45000)
            await page.wait_for_timeout(12000)
            html = await page.content()
            final_url = page.url
            if not pass_path or not token:
                html_pass_path, html_token = self._extract_pass_and_token(html)
                pass_path = pass_path or html_pass_path
                token = token or html_token
            await context.close()
            await browser.close()
            return pass_path, token, pass_body, final_url, html

    async def _get_session(self):
        if self.session is None or self.session.closed:
            timeout = ClientTimeout(total=60, connect=30, sock_read=30)
            proxy = self._get_random_proxy()
            if proxy:
                connector = ProxyConnector.from_url(proxy)
            else:
                connector = TCPConnector(limit=0, limit_per_host=0, keepalive_timeout=60, enable_cleanup_closed=True, force_close=False, use_dns_cache=True)
            self.session = ClientSession(timeout=timeout, connector=connector, headers={'User-Agent': self.base_headers["user-agent"]})
        return self.session

    async def extract(self, url: str, **kwargs) -> dict:
        """Extract DoodStream URL."""
        session = await self._get_session()

        async with session.get(url) as response:
            text = await response.text()
            response_url = str(response.url)

        pass_path, token = self._extract_pass_and_token(text)
        pass_body = None
        if not pass_path or not token:
            logger.info("DoodStream: direct HTML parse failed, trying browser fallback")
            pass_path, token, pass_body, response_url, text = await self._fetch_player_data_via_browser(url)

        if not pass_path or not token:
            snippet = (text or "")[:500].replace("\n", " ").replace("\r", " ")
            logger.warning(
                "DoodStream debug: response_url=%s pass_path=%s token_found=%s pass_body_found=%s html_snippet=%s",
                response_url,
                bool(pass_path),
                bool(token),
                bool(pass_body),
                snippet,
            )
            raise ExtractorError("Failed to extract URL pattern")

        parsed_response_url = urlparse(response_url)
        self.base_url = f"{parsed_response_url.scheme}://{parsed_response_url.netloc}"
        pass_url = f"{self.base_url}{pass_path}"
        referer = f"{self.base_url}/"
        headers = {"range": "bytes=0-", "referer": referer}

        response_text = pass_body
        if response_text is None:
            async with session.get(pass_url, headers=headers) as response:
                response_text = await response.text()
        
        timestamp_ms = str(int(time.time() * 1000))
        final_url = (
            f"{response_text}{self._random_suffix()}?token="
            f"{token}&expiry={timestamp_ms}"
        )

        self.base_headers["referer"] = referer
        return {
            "destination_url": final_url,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
