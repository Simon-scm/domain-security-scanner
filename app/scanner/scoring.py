SECURITY_HEADERS = {
    "strict-transport-security": 20,
    "content-security-policy": 15,
    "x-content-type-options": 10,
    "x-frame-options": 10,
    "referrer-policy": 10,
    "permissions-policy": 10,
}


def score_result(result) -> int:
    if not result.success:
        return 0

    score = 20 if result.tls_used and result.certificate_valid else 0

    if result.tls_version in {"TLSv1.2", "TLSv1.3"}:
        score += 15

    headers = {name.lower(): value for name, value in (result.headers or [])}
    for header, points in SECURITY_HEADERS.items():
        if headers.get(header):
            score += points

    if result.redirect_chain:
        first_hop = result.redirect_chain[0]
        if first_hop.from_url.startswith("http://") and first_hop.to_url.startswith("https://"):
            score += 10

    return max(0, min(score, 100))
