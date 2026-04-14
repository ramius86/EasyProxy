import logging
import random
import re
import socket
from urllib.parse import urlparse
from aiohttp import ClientSession, ClientTimeout, TCPConnector
from aiohttp.resolver import DefaultResolver
from aiohttp_socks import ProxyConnector
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

class StaticResolver(DefaultResolver):
    """Custom resolver to force specific IPs for domains (bypass hijacking)."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mapping = {}

    async def resolve(self, host, port=0, family=socket.AF_INET):
        if host in self.mapping:
            ip = self.mapping[host]
            logger.debug(f"StaticResolver: forcing {host} -> {ip}")
            # Format required by aiohttp: list of dicts
            return [{
                'hostname': host,
                'host': ip,
                'port': port,
                'family': family,
                'proto': 0,
                'flags': 0
            }]
        return await super().resolve(host, port, family)

class ExtractorError(Exception):
    pass

class MaxstreamExtractor:
    """Maxstream URL extractor."""

    def __init__(self, request_headers: dict, proxies: list = None):
        self.request_headers = request_headers
        self.base_headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.9",
            "accept-encoding": "gzip, deflate, br",
            "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "none",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
        }
        self.session = None
        self.mediaflow_endpoint = "hls_proxy"
        self.proxies = proxies or []
        self.resolver = StaticResolver()

    def _get_random_proxy(self):
        return random.choice(self.proxies) if self.proxies else None

    async def _get_session(self, proxy=None):
        """Get or create session, optionally with a specific proxy."""
        # Note: we use our custom resolver only for non-proxy requests
        # because proxies handle their own DNS resolution.
        
        timeout = ClientTimeout(total=45, connect=15, sock_read=30)
        if proxy:
            connector = ProxyConnector.from_url(proxy)
            return ClientSession(timeout=timeout, connector=connector, headers=self.base_headers)
        
        if self.session is None or self.session.closed:
            connector = TCPConnector(
                limit=0, 
                limit_per_host=0, 
                keepalive_timeout=60, 
                enable_cleanup_closed=True, 
                resolver=self.resolver # Use custom StaticResolver
            )
            self.session = ClientSession(timeout=timeout, connector=connector, headers=self.base_headers)
        return self.session

    async def _resolve_doh(self, domain: str) -> list[str]:
        """Resolve domain using DNS-over-HTTPS (Google) to bypass local DNS hijacking."""
        try:
            # Using Google DoH API
            url = f"https://dns.google/resolve?name={domain}&type=A"
            async with ClientSession(timeout=ClientTimeout(total=5)) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        ips = [ans['data'] for ans in data.get('Answer', []) if ans.get('type') == 1]
                        if ips:
                            logger.info(f"DoH resolved {domain} to {ips}")
                            return ips
        except Exception as e:
            logger.debug(f"DoH resolution failed for {domain}: {e}")
        return []

    async def _smart_request(self, url: str, method="GET", **kwargs):
        """Request with automatic retry using different proxies and resolver fallback on connection failure."""
        last_error = None
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Clear previous mapping for this domain to start fresh
        self.resolver.mapping.pop(domain, None)

        # Determine paths to try: Direct, Proxies, and then resolver override
        paths = []
        # Path 1: Direct (system DNS)
        paths.append({"proxy": None, "use_ip": None})
        
        # Path 2: Proxies (if any)
        if self.proxies:
            for p in self.proxies:
                paths.append({"proxy": p, "use_ip": None})
        
        # Path 3: DoH fallback (override resolver) if it's uprot or maxstream
        if "uprot.net" in domain or "maxstream" in domain:
            real_ips = await self._resolve_doh(domain)
            for ip in real_ips[:2]: # Try first 2 IPs
                paths.append({"proxy": None, "use_ip": ip})
        
        for path in paths:
            proxy = path["proxy"]
            use_ip = path["use_ip"]
            
            if use_ip:
                # CRITICAL: Must destroy old session to flush TCPConnector DNS cache!
                # Otherwise connector reuses cached (hijacked) IP even with new resolver mapping.
                if self.session and not self.session.closed:
                    await self.session.close()
                    self.session = None
                self.resolver.mapping[domain] = use_ip
                logger.info(f"DoH bypass: forcing {domain} -> {use_ip}")
            else:
                self.resolver.mapping.pop(domain, None)

            session = await self._get_session(proxy=proxy)
            try:
                async with session.request(method, url, **kwargs) as response:
                    if response.status < 400:
                        text = await response.text()
                        if proxy: await session.close()
                        return text
                    else:
                        logger.warning(f"Request to {url} failed (Status {response.status}) [Proxy: {proxy}, StaticIP: {use_ip}]")
            except Exception as e:
                logger.warning(f"Request to {url} failed (Error: {e}) [Proxy: {proxy}, StaticIP: {use_ip}]")
                last_error = e
                # If DoH attempt failed, destroy session so next IP gets fresh connector
                if use_ip and self.session and not self.session.closed:
                    await self.session.close()
                    self.session = None
            finally:
                if proxy and 'session' in locals() and not session.closed:
                    await session.close()
        
        raise ExtractorError(f"Connection failed for {url} after trying all paths. Last error: {last_error}")

    async def get_uprot(self, link: str):
        """Extract MaxStream URL from uprot redirect."""
        if "msf" in link:
            link = link.replace("msf", "mse")
        
        text = await self._smart_request(link)
        
        soup = BeautifulSoup(text, "lxml")
        a_tag = soup.find("a")
        if not a_tag:
            # Fallback: maybe the link is in a script or button
            button = soup.find("button", class_="button is-info")
            if button and button.parent.name == "a":
                maxstream_url = button.parent.get("href")
            else:
                logger.error(f"Could not find 'Continue' link in uprot page: {text[:500]}...")
                raise ExtractorError("Failed to find redirect link on uprot.net")
        else:
            maxstream_url = a_tag.get("href")
            
        return maxstream_url

    async def extract(self, url: str, **kwargs) -> dict:
        """Extract Maxstream URL."""
        maxstream_url = await self.get_uprot(url)
        
        text = await self._smart_request(maxstream_url, headers={"accept-language": "en-US,en;q=0.5"})

        # Try direct extraction first
        direct_match = re.search(r'sources:\s*\[\{src:\s*"([^"]+)"', text)
        if direct_match:
            final_url = direct_match.group(1)
            logger.info(f"Successfully extracted direct MaxStream URL: {final_url}")
            self.base_headers["referer"] = url
            return {
                "destination_url": final_url,
                "request_headers": self.base_headers,
                "mediaflow_endpoint": self.mediaflow_endpoint,
            }

        # Fallback to packer logic
        match = re.search(r"\}\('(.+)',.+,'(.+)'\.split", text)
        if not match:
            # Maybe it's a different packer signature?
            match = re.search(r"eval\(function\(p,a,c,k,e,d\).+?\}\('(.+?)',.+?,'(.+?)'\.split", text, re.S)
            
        if not match:
            logger.error(f"Failed to find packer script or direct source in: {text[:500]}...")
            raise ExtractorError("Failed to extract URL components")

        s1 = match.group(2)
        # Extract Terms
        terms = s1.split("|")
        try:
            urlset_index = terms.index("urlset")
            hls_index = terms.index("hls")
            sources_index = terms.index("sources")
        except ValueError as e:
            logger.error(f"Required terms missing in packer: {e}")
            raise ExtractorError(f"Missing components in packer: {e}")

        result = terms[urlset_index + 1 : hls_index]
        reversed_elements = result[::-1]
        first_part_terms = terms[hls_index + 1 : sources_index]
        reversed_first_part = first_part_terms[::-1]
        
        first_url_part = ""
        for fp in reversed_first_part:
            if "0" in fp:
                first_url_part += fp
            else:
                first_url_part += fp + "-"

        base_url = f"https://{first_url_part.rstrip('-')}.host-cdn.net/hls/"
        
        if len(reversed_elements) == 1:
            final_url = base_url + "," + reversed_elements[0] + ".urlset/master.m3u8"
        else:
            final_url = base_url
            for i, element in enumerate(reversed_elements):
                final_url += element + ","
            final_url = final_url.rstrip(",") + ".urlset/master.m3u8"

        self.base_headers["referer"] = url
        return {
            "destination_url": final_url,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
