import urllib.parse
import tldextract
import re
import socket

def normalize_url(url: str) -> dict:
    """
    Normalizes a given URL and extracts its structural components.
    Handles IDN (punycode) decoding via tldextract.
    """
    if not url.startswith(('http://', 'https://')):
        # Fallback if no scheme provided
        url = 'http://' + url

    # Lowercase the entire URL first to avoid parsing mismatches
    url = url.lower()

    parsed = urllib.parse.urlparse(url)
    
    # decode punycode host if idna encoding is present
    try:
        host = parsed.hostname.encode('utf-8').decode('idna') if parsed.hostname else ""
    except Exception:
        host = parsed.hostname if parsed.hostname else ""

    ext = tldextract.extract(host)
    
    subdomain = ext.subdomain
    root_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

    # Check if host is an IP address
    is_ip = False
    try:
        socket.inet_aton(host)
        is_ip = True
    except socket.error:
        pass
    
    # Also check for simple ipv4 pattern just in case
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        is_ip = True

    return {
        "original_url": url,
        "scheme": parsed.scheme,
        "host": host,
        "domain": ext.domain,      # Just the part without suffix
        "root_domain": root_domain,
        "subdomain": subdomain,
        "path": parsed.path,
        "query": parsed.query,
        "is_ip": is_ip
    }
