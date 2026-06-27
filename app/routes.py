from fastapi import APIRouter, HTTPException, Form
from fastapi.responses import  FileResponse, HTMLResponse
from google import genai
import json
import requests
from pathlib import Path
import html
import socket
from app.security import sanitize_input, validate_input, resolve_domain
from app.config import ABUSEIPDB_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

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
        result = []
        ai_request = []
        for ip in ips:
            try:
                response = requests.get(abuseip_api, headers=headers, params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=10).json()
                result.append(response)

                data = response["data"]
                out = {}
                for k, v in data.items():
                    if k in ('ipAddress', 'isPublic', 'isWhitelisted', 'abuseConfidenceScore', 'countryCode', 'usageType', 'isp', 'domain', 'isTor'):
                        out[k] = v
                
                ai_request.append(out)

            except socket.herror:
                print("Kein Reverse-DNS-Eintrag gefunden")
        
        client = genai.Client(api_key=GEMINI_API_KEY)
        interaction = client.interactions.create(
            model="gemini-3.5-flash",
            input=""" Answer as fast as possible. Convert the dmain scan results into dungeon Encouter evaluation. Only return one awnser for all scanned ips combined. 
            Answer example in json format:
            {
                "encounter": "example.com",
                "enemy_type": "Neutral Infrastructure Entity",
                "threat_level": "0-100",
                "loot": [
                    "Clean IP reputation",
                    "No recent abuse reports",
                    "Low-risk network footprint"
                ],
                "battle_result": "No hostile signals detected",
                "next_action": "Proceed, but remember: IP reputation does not verify page content."
            }
            
            Scan results:
            """
            + json.dumps(ai_request, ensure_ascii=False)
        )
        
        raw_ai_text = interaction.output_text or ""
        raw_ai_text = raw_ai_text.strip()

        if raw_ai_text.startswith("```"):
            raw_ai_text = (
                raw_ai_text
                .removeprefix("```json")
                .removeprefix("```")
                .removesuffix("```")
                .strip()
            )

        try:
            ai_data = json.loads(raw_ai_text)
        except json.JSONDecodeError as ex:
            print("JSON PARSE ERROR:")
            print(ex)

            ai_data = {
                "encounter": domain,
                "enemy_type": "Unknown Dungeon Entity",
                "threat_level": "UNKNOWN",
                "loot": [],
                "battle_result": "The dungeon oracle returned unreadable runes.",
                "next_action": "The scan completed, but the AI response could not be parsed as valid JSON.",
                "raw_ai_response": raw_ai_text,
            }

        ai_json = json.dumps(ai_data, indent=2, ensure_ascii=False)

        loot_items = ai_data.get("loot", [])
        loot_html = ""
        for item in loot_items:
            loot_html += f"<li>{html.escape(str(item))}</li>"
        
        template = (STATIC_DIR / "scan_result.html").read_text(encoding="utf-8")
        html_page = (
            template
            .replace("{{ encounter }}", html.escape(str(ai_data.get("encounter", domain))))
            .replace("{{ enemy_type }}", html.escape(str(ai_data.get("enemy_type", "Unknown Enemy"))))
            .replace("{{ threat_level }}", html.escape(str(ai_data.get("threat_level", "UNKNOWN"))))
            .replace("{{ battle_result }}", html.escape(str(ai_data.get("battle_result", "Unknown battle result"))))
            .replace("{{ next_action }}", html.escape(str(ai_data.get("next_action", "No next action available."))))
            .replace("{{ loot }}", loot_html)
            .replace("{{ ai_json }}", html.escape(ai_json))
        )

        return HTMLResponse(content=html_page)
                

    except ValueError as ex:
        raise HTTPException(status_code=400, detail=str(ex)) from ex
    
    return None