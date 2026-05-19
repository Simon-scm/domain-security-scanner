from urllib.parse import urlsplit
import socket
import ipaddress
import re


MAX_INPUT_LENGTH = 200

def sanitize_input(raw: str) -> str:
    if not raw:
        return ""

    # Trim and lowercase
    cleaned = raw.strip().lower()

    # Remove control characters (ASCII < 32 and DEL)
    cleaned = re.sub(r"[\x00-\x1F\x7F]", "", cleaned)

    # Normalize whitespace (multiple spaces -> single space)
    cleaned = re.sub(r"\s+", " ", cleaned)

    # Enforce max length
    if len(cleaned) > MAX_INPUT_LENGTH:
        cleaned = cleaned[:MAX_INPUT_LENGTH]

    return cleaned

def validate_input(input_sanitized: str) -> str:
    parsed_input = urlsplit(input_sanitized if "://" in input_sanitized else f"//{input_sanitized}")

    if parsed_input.username or parsed_input.password:
        raise ValueError("Username or password in domain not allowed")
    
    if parsed_input.port is not None:
        raise ValueError("ports not allowed")
    
    if parsed_input.scheme and parsed_input.scheme not in {"http", "https"}:
        raise ValueError("only http and https scheme allowed")

    domain = parsed_input.hostname
    if not domain:
        raise ValueError("Invalid domain")
    
    if domain == "localhost":
        raise ValueError("localhost is not allowed")

    if "." not in domain or len(domain) > 253 or not re.fullmatch(r"(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*", domain):
        raise ValueError("Invalid domain")

    try:
        ip = ipaddress.ip_address(domain)
    except ValueError:
        pass
    else: 
        raise ValueError("IP Address as input not allowed")
        
    return domain


def resolve_validate_domain(domain: str) -> set:

    try:
        sock = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ValueError("domain resolution failed")

    ips = set()
    for entry in sock:
        sockaddr = entry[4]
        ip = sockaddr[0]
        ips.add(ip)

    for ip in ips:
        current_ip = ipaddress.ip_address(ip)

        if current_ip.is_loopback:
            raise ValueError("loopback IP address not allowed")
        
        if current_ip.is_private:
            raise ValueError("private IP address not allowed")
        
        if current_ip.is_link_local:
            raise ValueError("local link IP address not allowed")
        
        if current_ip.is_multicast:
            raise ValueError("multicast IP address not allowed")
        
        if current_ip.is_reserved:
            raise ValueError("reserved IP address not allowed")

        if current_ip.is_unspecified:
            raise ValueError("unspecified IP address not allowed")

        if not current_ip.is_global:
            raise ValueError("non-public IP address not allowed")
    
    return ips


