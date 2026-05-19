from datetime import datetime, timezone
import json
import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.db.models import Scan
from app.db.session import SessionLocal, get_db

from urllib.parse import urlsplit
from app.scanner.engine import make_request
from app.scanner.scoring import score_result
from app.scanner.security import validate_input, sanitize_input

router = APIRouter()

class ScanRequest(BaseModel):
    domain: str = Field(min_length=1, max_length=200)


class ScanResponse(BaseModel):
    scan_id: str
    status: str


class ScanDetailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    domain: str
    status: str
    created_at: datetime
    score: int | None
    result_json: str | None
    warning: str | None


def normalize_input(input: str) -> str:
    input_sanitized = sanitize_input(input)
    domain = validate_input(input_sanitized)
    return [domain, input_sanitized]


def run_scan(scan_id: str, domain: str) -> None:
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        scan.status = "running"
        db.commit()

        result = make_request(domain)
        scan.result_json = (
            result.model_dump_json()
            if hasattr(result, "model_dump_json")
            else result.json()
        )
        scan.status = "completed" if result.success else "failed"
        scan.score = score_result(result)
        db.commit()
    except Exception as exc:
        db.rollback()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "failed"
            scan.result_json = json.dumps({
                "error_type": "scan_error",
                "error_message": str(exc),
            })
            db.commit()
    finally:
        db.close()


@router.post("/scan", response_model=ScanResponse)
def create_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    #Erstellt einen neuen Scan-Eintrag in der Datenbank.
    scan_id = str(uuid.uuid4())
    try:
        normalized_input = normalize_input(request.domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    normalized_domain = normalized_input[0]
    input_sanitized = normalized_input[1]

    #Warning eintragen falls Path/Query/Fragment im Input enthalten sind.
    sanitized_parts = urlsplit(input_sanitized)
    if sanitized_parts.path or sanitized_parts.query or sanitized_parts.fragment:
        warning_message = "Input contained path/query/fragment. Only the hostname was scanned."
    else:
        warning_message = None
    
    scan = Scan(
        id=scan_id,
        domain=normalized_domain,
        input_sanitized=input_sanitized,
        status="queued",
        created_at=datetime.now(timezone.utc),
        warning=warning_message
    )
    
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(run_scan, scan_id, normalized_domain)
    
    return ScanResponse(scan_id=scan_id, status="queued")


@router.get("/scan/{scan_id}", response_model=ScanDetailResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    #Ruft Scan-Details anhand der Scan-ID ab.
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return scan
