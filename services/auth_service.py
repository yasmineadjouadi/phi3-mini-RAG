from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from database.db import SessionLocal
from database.models import User
import os
from dotenv import load_dotenv

load_dotenv()

ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 60 * 24  # 24h


def jwt_secret() -> str:
    """Lit SECRET_KEY après chargement du .env (évite décalage encode / décode)."""
    return (os.getenv("SECRET_KEY") or "une_cle_fixe_longue_et_secrete_ti2026").strip()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

DEFAULT_PASSWORD = "Passw0rd@2o26"


# ── Dépendance DB ─────────────────────────────────────────────
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Password ──────────────────────────────────────────────────
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ── JWT ───────────────────────────────────────────────────────
def create_token(data: dict) -> str:
    payload = data.copy()
    if payload.get("sub") is not None:
        payload["sub"] = str(payload["sub"])
    payload["exp"] = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    return jwt.encode(payload, jwt_secret(), algorithm=ALGORITHM)


# ── get_current_user ──────────────────────────────────────────
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token invalide ou expiré",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        token = (credentials.credentials or "").strip()
        token = token.replace("\n", "").replace("\r", "").replace("\t", "")
        if not token:
            raise credentials_exception
        payload = jwt.decode(token, jwt_secret(), algorithms=[ALGORITHM])
    except JWTError:
        raise credentials_exception

    raw_sub = payload.get("sub")
    if raw_sub is None:
        raise credentials_exception
    try:
        user_id = int(raw_sub)
    except (TypeError, ValueError):
        raise credentials_exception

    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if user is None:
        raise credentials_exception
    return user


# ── Vérifie que l'utilisateur est superadmin ──────────────────
def require_superadmin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "superadmin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Accès réservé au superadmin"
        )
    return current_user