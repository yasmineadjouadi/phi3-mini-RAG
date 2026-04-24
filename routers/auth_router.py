from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from database.models import User
from services.auth_service import (
    get_db, hash_password, verify_password,
    create_token, get_current_user, require_superadmin,
    DEFAULT_PASSWORD
)

router = APIRouter()


# ── Schémas ───────────────────────────────────────────────────
class CreateUserRequest(BaseModel):
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

class ChangePasswordRequest(BaseModel):
    user_id: int

class UpdatePasswordRequest(BaseModel):
    old_password: str
    new_password: str

class UpdateProfileRequest(BaseModel):
    langue: Optional[str] = None
    theme: Optional[str] = None


class NgrokUrlRequest(BaseModel):
    llm_api_url: str


# ── POST /auth/create-user  (superadmin seulement) ────────────
@router.post("/create-user", status_code=201)
def create_user(
    body: CreateUserRequest,
    db: Session = Depends(get_db),
    _: User = Depends(require_superadmin)
):
    existing = db.query(User).filter(User.email == body.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email déjà utilisé")

    user = User(
        email=body.email,
        password_hash=hash_password(body.password),
        role="user"
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"id": user.id, "email": user.email, "role": user.role}


# ── POST /auth/login ──────────────────────────────────────────
@router.post("/login")
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email).first()

    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou mot de passe incorrect"
        )
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Compte désactivé")

    token = create_token({"sub": user.id, "role": user.role})
    return {"access_token": token, "token_type": "bearer", "role": user.role}


# ── GET /auth/me ──────────────────────────────────────────────
@router.get("/me")
def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id":         current_user.id,
        "email":      current_user.email,
        "role":       current_user.role,
        "is_active":  current_user.is_active,
        "langue":     getattr(current_user, "langue", "fr"),
        "theme":      getattr(current_user, "theme", "dark"),
        "created_at": str(current_user.created_at)
    }


# ── PUT /auth/me  (modifier profil) ──────────────────────────
@router.put("/me")
def update_me(
    body: UpdateProfileRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if body.langue:
        current_user.langue = body.langue
    if body.theme:
        current_user.theme = body.theme
    db.commit()
    return {
        "id":     current_user.id,
        "email":  current_user.email,
        "role":   current_user.role,
        "langue": current_user.langue,
        "theme":  current_user.theme,
    }


# ── PUT /auth/change-password ─────────────────────────────────
@router.put("/change-password")
def change_password(
    body: UpdatePasswordRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not verify_password(body.old_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="Ancien mot de passe incorrect")

    current_user.password_hash = hash_password(body.new_password)
    db.commit()
    return {"message": "Mot de passe mis à jour"}


# ── POST /auth/reset-password  (superadmin) ───────────────────
@router.post("/reset-password")
def reset_password(
    body: ChangePasswordRequest,
    db: Session = Depends(get_db),
    _: User = Depends(require_superadmin)
):
    user = db.query(User).filter(User.id == body.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")

    user.password_hash = hash_password(DEFAULT_PASSWORD)
    db.commit()
    return {"message": f"Mot de passe réinitialisé → {DEFAULT_PASSWORD}"}


# ── PUT /auth/toggle-user  (superadmin) ───────────────────────
@router.put("/toggle-user/{user_id}")
def toggle_user(
    user_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_superadmin)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    if user.role == "superadmin":
        raise HTTPException(status_code=400, detail="Impossible de désactiver le superadmin")

    user.is_active = not user.is_active
    db.commit()
    status_msg = "activé" if user.is_active else "désactivé"
    return {"message": f"Compte {status_msg}", "is_active": user.is_active}


# ── GET /auth/users  (superadmin) ─────────────────────────────
@router.get("/users")
def list_users(
    db: Session = Depends(get_db),
    _: User = Depends(require_superadmin)
):
    users = db.query(User).all()
    return [
        {
            "id": u.id,
            "email": u.email,
            "role": u.role,
            "is_active": u.is_active,
            "created_at": str(u.created_at)
        }
        for u in users
    ]


# ── PUT /auth/ngrok-url  (superadmin) — LLM_API_URL dans .env ─
@router.put("/ngrok-url")
def update_ngrok_url(
    body: NgrokUrlRequest,
    _: User = Depends(require_superadmin),
):
    url = body.llm_api_url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL invalide (http/https requis)")

    from services.env_update import update_dotenv_value
    from services.llm_enricher import set_llm_api_url

    update_dotenv_value("LLM_API_URL", url)
    set_llm_api_url(url)
    return {"message": "LLM_API_URL mis à jour et rechargé", "llm_api_url": url}


# ── GET /auth/logs  (superadmin) ──────────────────────────────
@router.get("/logs")
def get_logs(
    db: Session = Depends(get_db),
    _: User = Depends(require_superadmin),
    limit: int = 100
):
    from database.models import ActivityLog
    logs = db.query(ActivityLog).order_by(ActivityLog.created_at.desc()).limit(limit).all()
    return [
        {
            "id":          l.id,
            "ip":          l.ip,
            "method":      l.method,
            "path":        l.path,
            "status_code": l.status_code,
            "duration_ms": l.duration_ms,
            "created_at":  str(l.created_at)
        }
        for l in logs
    ]