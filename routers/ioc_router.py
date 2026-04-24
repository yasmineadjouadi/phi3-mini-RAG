from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from services.ioc_scan_service import analyze_indicator_for_user
from services.auth_service import get_current_user, get_db
from database.models import User

router = APIRouter()


class IOCRequest(BaseModel):
    indicator: str


class BulkIOCRequest(BaseModel):
    indicators: list[str] = Field(..., min_length=1)
    force_rag: bool = False


@router.post("/analyze")
def analyze(
    body: IOCRequest,
    force_rag: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = analyze_indicator_for_user(
        db, current_user.id, body.indicator.strip(), force_rag=force_rag
    )
    if not result["ok"]:
        return JSONResponse(result["error"], status_code=result["status_code"])
    return result["payload"]


@router.post("/bulk")
def bulk_analyze(
    body: BulkIOCRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    results: list[dict] = []
    for raw in body.indicators:
        indicator = (raw or "").strip()
        if not indicator:
            results.append(
                {
                    "indicator": raw,
                    "ok": False,
                    "status_code": 400,
                    "error": {"error": "Indicateur vide"},
                }
            )
            continue
        r = analyze_indicator_for_user(
            db, current_user.id, indicator, force_rag=body.force_rag
        )
        if r["ok"]:
            results.append({"indicator": indicator, "ok": True, "data": r["payload"]})
        else:
            results.append(
                {
                    "indicator": indicator,
                    "ok": False,
                    "status_code": r["status_code"],
                    "error": r["error"],
                }
            )
    return {"count": len(results), "results": results}


@router.get("/debug-hash")
def debug_hash(_: User = Depends(get_current_user)):
    from services.hash_services import get_hash_report
    from services.rag_gate import collect_ti_signals

    raw = get_hash_report(
        "1ac890ff8a824da863fbf28eb585438fd7654abd2653f8d49537fc27bce78704"
    )
    signals = collect_ti_signals("hash", raw)
    return {
        "raw_verdict": raw.get("risk_level"),
        "signals": signals,
        "vt_malicious": raw.get("detection", {}).get("malicious"),
    }
