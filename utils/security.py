import ipaddress
import socket
import logging
import asyncio
import os
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

PUBLIC_URL = os.environ.get("PUBLIC_URL", "")

def get_base_url(request) -> str:
    """Safely gets the base URL preventing Host Header Injection."""
    if PUBLIC_URL:
        return PUBLIC_URL.rstrip('/')
        
    scheme = request.headers.get("X-Forwarded-Proto", request.scheme)
    host = request.headers.get("X-Forwarded-Host", request.host)
    
    if host and re.match(r"^[a-zA-Z0-9.-]+(:[0-9]+)?$", host):
        return f"{scheme}://{host}"
        
    return f"{scheme}://127.0.0.1:7860" # Safe fallback

async def is_safe_url(url: str) -> bool:
    """
    Checks if a URL is safe to request (prevents SSRF).
    Resolves the hostname and checks if it points to a private/local IP.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
            
        loop = asyncio.get_running_loop()
        
        try:
            # Resolve host to IP
            addr_info = await loop.getaddrinfo(hostname, None)
            for info in addr_info:
                ip_str = info[4][0]
                ip = ipaddress.ip_address(ip_str)
                # Check for private, loopback, link-local, multicast, reserved
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                    logger.warning(f"SSRF attempt blocked! {url} resolves to private IP {ip_str}")
                    return False
        except socket.gaierror:
            # If it doesn't resolve, it will fail anyway during the request.
            # But we allow it to proceed to the standard error handling.
            pass
            
        return True
    except Exception as e:
        logger.error(f"Error validating URL {url}: {e}")
        return False
