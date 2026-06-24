from fastapi import APIRouter, HTTPException, Form
import requests
import socket
from app.security import sanitize_input, validate_input, resolve_domain
from app.config import ABUSEIPDB_API_KEY


router = APIRouter()

@router.post("/scan")
def create_scan(url: str = Form(...)):
    try:
        sanitized_input = sanitize_input(url)
        domain = validate_input(sanitized_input)
        ips = resolve_domain(domain)
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        abuseip_api = "https://api.abuseipdb.com/api/v2/check"
        for ip in ips:
            try:
                result = requests.get(abuseip_api, headers=headers, params={"ipAddress": ip, "maxAgeInDays": 90}).json()
                print(result)

            except socket.herror:
                print("Kein Reverse-DNS-Eintrag gefunden")

    except ValueError as ex:
        raise HTTPException(status_code=400, detail=str(ex)) from ex
    
    print(ips)
    
    return None