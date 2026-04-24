from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.orm import Session
from typing import Optional
from database.models import User, ScanHistory
from services.auth_service import get_current_user, get_db
from datetime import datetime
import json
import io
import csv

router = APIRouter()


def _get_scans(db, user_id, ioc_type=None, risk_level=None):
    query = db.query(ScanHistory).filter(ScanHistory.user_id == user_id)
    if ioc_type:
        query = query.filter(ScanHistory.ioc_type == ioc_type)
    if risk_level:
        query = query.filter(ScanHistory.risk_level == risk_level)
    return query.order_by(ScanHistory.created_at.desc()).all()


@router.get("/json")
def export_json(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    ioc_type: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
):
    scans = _get_scans(db, current_user.id, ioc_type, risk_level)
    data = {
        "exported_at": str(datetime.utcnow()),
        "user": current_user.email,
        "total": len(scans),
        "scans": [
            {
                "id": s.id,
                "indicator": s.indicator,
                "ioc_type": s.ioc_type,
                "risk_level": s.risk_level,
                "risk_score": s.risk_score,
                "final_verdict": s.final_verdict,
                "is_favorite": s.is_favorite,
                "created_at": str(s.created_at),
            }
            for s in scans
        ]
    }
    content = json.dumps(data, indent=2, ensure_ascii=False)
    return StreamingResponse(
        io.BytesIO(content.encode("utf-8")),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=export_ti.json"}
    )


@router.get("/pdf")
def export_pdf(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    ioc_type: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
):
    scans = _get_scans(db, current_user.id, ioc_type, risk_level)

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
    except ImportError:
        return JSONResponse({"error": "pip install reportlab"}, status_code=500)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("Threat Intelligence — Rapport d'export", styles["Title"]))
    elements.append(Paragraph(f"Généré le : {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC", styles["Normal"]))
    elements.append(Paragraph(f"Utilisateur : {current_user.email}", styles["Normal"]))
    elements.append(Spacer(1, 20))

    headers = ["#", "Indicateur", "Type", "Verdict", "Score", "Date"]
    rows = [headers]
    for s in scans:
        rows.append([
            str(s.id),
            s.indicator[:40] + "..." if len(s.indicator) > 40 else s.indicator,
            s.ioc_type or "-",
            s.final_verdict or "-",
            str(s.risk_score) if s.risk_score is not None else "-",
            str(s.created_at)[:16] if s.created_at else "-",
        ])

    table = Table(rows, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(table)

    doc.build(elements)
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=export_ti.pdf"}
    )


@router.get("/csv")
def export_csv(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    ioc_type: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
):
    scans = _get_scans(db, current_user.id, ioc_type, risk_level)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Indicateur", "Type", "Verdict", "Score", "Favori", "Date"])
    for s in scans:
        writer.writerow([
            s.id,
            s.indicator,
            s.ioc_type or "-",
            s.final_verdict or "-",
            s.risk_score if s.risk_score is not None else "-",
            "oui" if s.is_favorite else "non",
            str(s.created_at)[:16] if s.created_at else "-",
        ])

    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8-sig")),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=export_ti.csv"}
    )