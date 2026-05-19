from datetime import datetime, timezone
import socket
import ssl
from urllib.parse import urljoin

import httpx
from pydantic import BaseModel, Field

from app.scanner.security import resolve_validate_domain, validate_input


SECURITY_HEADER_NAMES = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]


class RedirectHop(BaseModel):
    from_url: str
    to_url: str
    status_code: int
    resolved_ips: set[str] = Field(default_factory=set)
    blocked: bool = False
    block_reason: str | None = None


class SecurityHeaderResult(BaseModel):
    name: str
    present: bool
    value: str | None = None


class CertificateInfo(BaseModel):
    subject: str | None = None
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    expired: bool | None = None


class RequestResponse(BaseModel):
    success: bool
    error_type: str | None = None
    error_message: str | None = None
    requested_url: str
    last_attempted_url: str
    redirect_chain: list[RedirectHop] = Field(default_factory=list)
    final_url: str | None = None
    status_code: int | None = None
    headers: list[tuple[str, str]] | None = None
    security_headers: list[SecurityHeaderResult] = Field(default_factory=list)
    response_size: int | None = None
    final_ip_versions: set[str] | None = None
    connection_time_ms: int | None = None
    tls_used: bool = False
    tls_version: str | None = None
    certificate_valid: bool | None = None
    certificate: CertificateInfo | None = None


def get_ip_versions(ips: set[str]) -> set[str]:
    return {"IPv6" if ":" in ip else "IPv4" for ip in ips}


def _request_head_or_get(client: httpx.Client, url: str) -> httpx.Response:
    response = client.head(url)
    if response.status_code in {405, 403}:
        response = client.get(url)
    return response


def _format_cert_name(parts) -> str | None:
    values = []
    for group in parts or []:
        for key, value in group:
            if key in {"commonName", "organizationName"}:
                values.append(value)
    return ", ".join(values) if values else None


def _parse_cert_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def get_certificate_info(domain: str) -> tuple[CertificateInfo | None, str | None]:
    context = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=5.0) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=domain) as tls_socket:
            cert = tls_socket.getpeercert()
            not_after = _parse_cert_datetime(cert.get("notAfter"))
            certificate = CertificateInfo(
                subject=_format_cert_name(cert.get("subject")),
                issuer=_format_cert_name(cert.get("issuer")),
                not_before=cert.get("notBefore"),
                not_after=cert.get("notAfter"),
                expired=not_after < datetime.now(timezone.utc) if not_after else None,
            )
            return certificate, tls_socket.version()


def analyze_security_headers(headers: httpx.Headers) -> list[SecurityHeaderResult]:
    return [
        SecurityHeaderResult(
            name=name,
            present=name in headers,
            value=headers.get(name),
        )
        for name in SECURITY_HEADER_NAMES
    ]


def follow_redirects(
    client: httpx.Client,
    response: httpx.Response,
    current_url: str,
) -> tuple[list[RedirectHop], httpx.Response, str]:
    redirect_status = {301, 302, 303, 307, 308}
    redirect_chain: list[RedirectHop] = []

    while response.status_code in redirect_status and len(redirect_chain) < client.max_redirects:
        location = response.headers.get("location")
        if not location:
            break

        next_url = urljoin(current_url, location)
        try:
            next_domain = validate_input(next_url)
            resolved_ips = resolve_validate_domain(next_domain)
        except ValueError as exc:
            redirect_chain.append(RedirectHop(
                from_url=current_url,
                to_url=next_url,
                status_code=response.status_code,
                blocked=True,
                block_reason=str(exc),
            ))
            break

        redirect_chain.append(RedirectHop(
            from_url=current_url,
            to_url=next_url,
            status_code=response.status_code,
            resolved_ips=resolved_ips,
        ))
        current_url = next_url
        response = _request_head_or_get(client, current_url)

    return redirect_chain, response, current_url


def check_http_redirect(client: httpx.Client, domain: str) -> list[RedirectHop]:
    current_url = f"http://{domain}/"
    try:
        response = _request_head_or_get(client, current_url)
        redirect_chain, _, _ = follow_redirects(client, response, current_url)
        return redirect_chain
    except (httpx.RequestError, httpx.TimeoutException, ValueError):
        return []


def make_request(domain: str) -> RequestResponse:
    current_url = f"https://{domain}/"
    result = RequestResponse(
        success=False,
        requested_url=current_url,
        last_attempted_url=current_url,
    )

    try:
        ips = resolve_validate_domain(domain)

        with httpx.Client(max_redirects=5, timeout=5.0, follow_redirects=False) as client:
            redirect_chain = check_http_redirect(client, domain)
            response = _request_head_or_get(client, current_url)
            https_redirect_chain, response, current_url = follow_redirects(client, response, current_url)
            result.redirect_chain = redirect_chain + https_redirect_chain
            result.last_attempted_url = current_url

            if result.redirect_chain and result.redirect_chain[-1].blocked:
                result.error_type = "blocked_redirect"
                result.error_message = result.redirect_chain[-1].block_reason
                result.last_attempted_url = result.redirect_chain[-1].to_url
                return result

            headers = list(response.headers.multi_items())
            content_length = response.headers.get("content-length")
            response_size = int(content_length) if content_length and content_length.isdigit() else len(response.content)
            final_ips = https_redirect_chain[-1].resolved_ips if https_redirect_chain else ips

            certificate = None
            tls_version = None
            tls_used = str(response.url).startswith("https://")
            if tls_used:
                certificate, tls_version = get_certificate_info(response.url.host or domain)

            result.success = True
            result.final_url = str(response.url)
            result.status_code = response.status_code
            result.headers = headers
            result.security_headers = analyze_security_headers(response.headers)
            result.response_size = response_size
            result.final_ip_versions = get_ip_versions(final_ips)
            result.connection_time_ms = int(response.elapsed.total_seconds() * 1000)
            result.tls_used = tls_used
            result.tls_version = tls_version
            result.certificate_valid = True if tls_used else None
            result.certificate = certificate
    except httpx.TimeoutException as exc:
        result.error_type = "timeout"
        result.error_message = str(exc)
    except httpx.RequestError as exc:
        result.error_type = "request_error"
        result.error_message = str(exc)
        if exc.request:
            result.last_attempted_url = str(exc.request.url)
    except (ssl.SSLError, socket.timeout, OSError) as exc:
        result.error_type = "tls_or_network_error"
        result.error_message = str(exc)
    except ValueError as exc:
        result.error_type = "validation_error"
        result.error_message = str(exc)

    return result
