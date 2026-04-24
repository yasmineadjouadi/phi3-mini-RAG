from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from database.models import User, ScanHistory
from services.auth_service import get_current_user, get_db

router = APIRouter()


@router.get("/")
def get_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    base = db.query(ScanHistory).filter(ScanHistory.user_id == current_user.id)

    total = base.count()

    # Par type d'IOC
    by_type = (
        db.query(ScanHistory.ioc_type, func.count(ScanHistory.id))
        .filter(ScanHistory.user_id == current_user.id)
        .group_by(ScanHistory.ioc_type)
        .all()
    )

    # Par verdict
    by_verdict = (
        db.query(ScanHistory.final_verdict, func.count(ScanHistory.id))
        .filter(ScanHistory.user_id == current_user.id)
        .group_by(ScanHistory.final_verdict)
        .all()
    )

    # Score moyen
    avg_score = (
        db.query(func.avg(ScanHistory.risk_score))
        .filter(ScanHistory.user_id == current_user.id)
        .scalar()
    )

    # Derniers 5 scans
    recent = (
        base.order_by(ScanHistory.created_at.desc())
        .limit(5)
        .all()
    )

    # Favoris
    favorites_count = base.filter(ScanHistory.is_favorite == True).count()

    return {
        "total_scans": total,
        "favorites": favorites_count,
        "avg_risk_score": round(float(avg_score), 2) if avg_score else 0,
        "by_type": {ioc_type: count for ioc_type, count in by_type},
        "by_verdict": {verdict: count for verdict, count in by_verdict},
        "recent_scans": [
            {
                "id": s.id,
                "indicator": s.indicator,
                "ioc_type": s.ioc_type,
                "final_verdict": s.final_verdict,
                "risk_score": s.risk_score,
                "created_at": str(s.created_at),
            }
            for s in recent
        ]
    }