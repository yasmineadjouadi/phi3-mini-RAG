from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from database.models import User, ChatSession, ChatMessage
from services.auth_service import get_current_user, get_db

router = APIRouter()


# ── Schémas ───────────────────────────────────────────────────
class CreateSessionRequest(BaseModel):
    title: Optional[str] = "Nouvelle conversation"

class SendMessageRequest(BaseModel):
    session_id: int
    message: str


# ── POST /chat/sessions — créer une session ───────────────────
@router.post("/sessions", status_code=201)
def create_session(
    body: CreateSessionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    session = ChatSession(
        user_id=current_user.id,
        title=body.title
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return {"id": session.id, "title": session.title, "created_at": str(session.created_at)}


# ── GET /chat/sessions — liste des sessions ───────────────────
@router.get("/sessions")
def list_sessions(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    sessions = (
        db.query(ChatSession)
        .filter(ChatSession.user_id == current_user.id)
        .order_by(ChatSession.created_at.desc())
        .all()
    )
    return [
        {"id": s.id, "title": s.title, "created_at": str(s.created_at)}
        for s in sessions
    ]


# ── GET /chat/sessions/{id}/messages — messages d'une session ─
@router.get("/sessions/{session_id}/messages")
def get_messages(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    session = db.query(ChatSession).filter(
        ChatSession.id == session_id,
        ChatSession.user_id == current_user.id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session introuvable")

    messages = (
        db.query(ChatMessage)
        .filter(ChatMessage.session_id == session_id)
        .order_by(ChatMessage.created_at.asc())
        .all()
    )
    return {
        "session_id": session_id,
        "title": session.title,
        "messages": [
            {
                "id": m.id,
                "role": m.role,
                "content": m.content,
                "created_at": str(m.created_at)
            }
            for m in messages
        ]
    }


# ── POST /chat/sessions/{id}/messages — ajouter un message (user uniquement)
@router.post("/sessions/{session_id}/messages", status_code=201)
def add_message(
    session_id: int,
    body: SendMessageRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    session = db.query(ChatSession).filter(
        ChatSession.id == session_id,
        ChatSession.user_id == current_user.id,
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session introuvable")

    message = ChatMessage(
        session_id=session_id,
        role="user",
        content=body.message,
    )
    db.add(message)
    db.commit()
    db.refresh(message)
    return {"id": message.id, "role": message.role, "content": message.content}


# ── DELETE /chat/sessions/{id} — supprimer une session ────────
@router.delete("/sessions/{session_id}")
def delete_session(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    session = db.query(ChatSession).filter(
        ChatSession.id == session_id,
        ChatSession.user_id == current_user.id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session introuvable")

    db.query(ChatMessage).filter(ChatMessage.session_id == session_id).delete()
    db.delete(session)
    db.commit()
    return {"message": "Session supprimée"}


# ── PUT /chat/sessions/{id} — renommer une session ────────────
@router.put("/sessions/{session_id}")
def rename_session(
    session_id: int,
    body: CreateSessionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    session = db.query(ChatSession).filter(
        ChatSession.id == session_id,
        ChatSession.user_id == current_user.id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session introuvable")

    session.title = body.title
    db.commit()
    return {"id": session.id, "title": session.title}