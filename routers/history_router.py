from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import Optional
from database.models import User, ScanHistory
from services.auth_service import get_current_user, get_db

router = APIRouter()


@router.get("/")
def get_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    ioc_type: Optional[str] = Query(None, description="Filtrer par type: ip, hash, domain, url, mail, cve"),
    risk_level: Optional[str] = Query(None, description="Filtrer par niveau: low, medium, high, critical"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    query = db.query(ScanHistory).filter(ScanHistory.user_id == current_user.id)

    if ioc_type:
        query = query.filter(ScanHistory.ioc_type == ioc_type)
    if risk_level:
        query = query.filter(ScanHistory.risk_level == risk_level)

    total = query.count()
    scans = query.order_by(ScanHistory.created_at.desc()).offset(offset).limit(limit).all()

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "results": [
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


@router.put("/{scan_id}/favorite")
def toggle_favorite(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = db.query(ScanHistory).filter(
        ScanHistory.id == scan_id,
        ScanHistory.user_id == current_user.id
    ).first()

    if not scan:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Scan introuvable")

    scan.is_favorite = not scan.is_favorite
    db.commit()
    return {"id": scan_id, "is_favorite": scan.is_favorite}


@router.delete("/{scan_id}")
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = db.query(ScanHistory).filter(
        ScanHistory.id == scan_id,
        ScanHistory.user_id == current_user.id
    ).first()

    if not scan:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Scan introuvable")

    db.delete(scan)
    db.commit()
    return {"message": "Scan supprimé"}

@router.get("/favorites")
def get_favorites(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scans = (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == current_user.id, ScanHistory.is_favorite == True)
        .order_by(ScanHistory.created_at.desc())
        .all()
    )
    return {
        "total": len(scans),
        "results": [
            {
                "id": s.id,
                "indicator": s.indicator,
                "ioc_type": s.ioc_type,
                "risk_level": s.risk_level,
                "risk_score": s.risk_score,
                "final_verdict": s.final_verdict,
                "created_at": str(s.created_at),
            }
            for s in scans
        ]
    }


@router.get("/search")
def search_history(
    q: str = Query(..., description="Mot clé à rechercher dans les indicateurs"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scans = (
        db.query(ScanHistory)
        .filter(
            ScanHistory.user_id == current_user.id,
            ScanHistory.indicator.contains(q)
        )
        .order_by(ScanHistory.created_at.desc())
        .limit(50)
        .all()
    )
    return {
        "query": q,
        "total": len(scans),
        "results": [
            {
                "id": s.id,
                "indicator": s.indicator,
                "ioc_type": s.ioc_type,
                "risk_level": s.risk_level,
                "risk_score": s.risk_score,
                "final_verdict": s.final_verdict,
                "created_at": str(s.created_at),
            }
            for s in scans
        ]
    }