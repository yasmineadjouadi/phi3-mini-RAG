from fastapi import APIRouter, Request, Form, Depends
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from services.hash_services import get_hash_report
from services.auth_service import get_current_user, get_db
from database.db import SessionLocal
from database.models import ScanHistory, User
from sqlalchemy import func
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])
templates = Jinja2Templates(directory="templates")


# ── Dashboard HTML ────────────────────────────────────────────
@router.get("/", response_class=HTMLResponse)
def dashboard_home(request: Request, _: User = Depends(get_current_user)):
    db = SessionLocal()

    total_scans = db.query(ScanHistory).count()
    high   = db.query(ScanHistory).filter(ScanHistory.risk_level == "High").count()
    medium = db.query(ScanHistory).filter(ScanHistory.risk_level == "Medium").count()
    low    = db.query(ScanHistory).filter(ScanHistory.risk_level == "Low").count()
    by_source = db.query(ScanHistory.source, func.count(ScanHistory.id)).group_by(ScanHistory.source).all()
    scans = db.query(ScanHistory).order_by(ScanHistory.id.desc()).all()
    db.close()

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request":     request,
            "total_scans": total_scans,
            "risk_levels": {"High": high, "Medium": medium, "Low": low},
            "by_source":   dict(by_source),
            "scans":       scans
        }
    )


# ── Scan hash depuis Dashboard ────────────────────────────────
@router.post("/scan", response_class=HTMLResponse)
def dashboard_scan(
    request: Request,
    hash_value: str = Form(...),
    _: User = Depends(get_current_user),
):
    result = get_hash_report(hash_value)
    if "error" in result:
        return templates.TemplateResponse(
            "dashboard.html",
            {"request": request, "error": "Hash not found"}
        )
    return templates.TemplateResponse(
        "result.html",
        {"request": request, "data": result}
    )


# ── GET /dashboard/stats (JSON — pour le front chatbot) ───────
@router.get("/stats")
def get_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    base = db.query(ScanHistory).filter(ScanHistory.user_id == current_user.id)
    total = base.count()

    by_type = (
        db.query(ScanHistory.ioc_type, func.count(ScanHistory.id))
        .filter(ScanHistory.user_id == current_user.id)
        .group_by(ScanHistory.ioc_type)
        .all()
    )

    by_verdict = (
        db.query(ScanHistory.final_verdict, func.count(ScanHistory.id))
        .filter(ScanHistory.user_id == current_user.id)
        .group_by(ScanHistory.final_verdict)
        .all()
    )

    avg_score = (
        db.query(func.avg(ScanHistory.risk_score))
        .filter(ScanHistory.user_id == current_user.id)
        .scalar()
    )

    # Top 5 IOCs dangereux de la semaine
    week_ago = datetime.utcnow() - timedelta(days=7)
    top5 = (
        db.query(ScanHistory)
        .filter(
            ScanHistory.user_id == current_user.id,
            ScanHistory.created_at >= week_ago,
            ScanHistory.risk_score != None
        )
        .order_by(ScanHistory.risk_score.desc())
        .limit(5)
        .all()
    )

    return {
        "total_scans":   total,
        "avg_risk_score": round(float(avg_score), 2) if avg_score else 0,
        "by_type":       {t: c for t, c in by_type},
        "by_verdict":    {v: c for v, c in by_verdict},
        "top5_dangerous": [
            {
                "indicator":     s.indicator,
                "ioc_type":      s.ioc_type,
                "risk_score":    s.risk_score,
                "final_verdict": s.final_verdict,
                "created_at":    str(s.created_at),
            }
            for s in top5
        ]
    }


# ── GET /dashboard/scans-per-day (7 derniers jours) ──────────
@router.get("/scans-per-day")
def scans_per_day(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    week_ago = datetime.utcnow() - timedelta(days=7)

    results = (
        db.query(
            func.date(ScanHistory.created_at).label("date"),
            func.count(ScanHistory.id).label("count")
        )
        .filter(
            ScanHistory.user_id == current_user.id,
            ScanHistory.created_at >= week_ago
        )
        .group_by(func.date(ScanHistory.created_at))
        .order_by(func.date(ScanHistory.created_at))
        .all()
    )

    # Remplir les jours manquants avec 0
    data = {}
    for i in range(7):
        day = (datetime.utcnow() - timedelta(days=6 - i)).strftime("%Y-%m-%d")
        data[day] = 0
    for row in results:
        data[str(row.date)] = row.count

    return {
        "period": "7 derniers jours",
        "data": [{"date": d, "count": c} for d, c in data.items()]
    }