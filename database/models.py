from sqlalchemy import Column, Integer, String, Text, JSON, DateTime, Boolean, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from .db import Base


class User(Base):
    __tablename__ = "users"

    id            = Column(Integer, primary_key=True, index=True)
    email         = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role          = Column(String(50), default="user")
    is_active     = Column(Boolean, default=True)
    langue        = Column(String(10), default="fr")   # ← ajout
    theme         = Column(String(10), default="dark")  # ← ajout
    created_at = Column(DateTime, server_default=func.now())

    sessions = relationship("ChatSession", back_populates="user")
    scans    = relationship("ScanHistory", back_populates="user")

class IOC(Base):
    __tablename__ = "iocs"

    id         = Column(Integer, primary_key=True, index=True)
    value      = Column(String(255), index=True)
    type       = Column(String(50), index=True)
    risk_level = Column(String(50))
    risk_score = Column(Integer)
    confidence = Column(String(50))
    source     = Column(String(255))
    data       = Column(JSON)
    created_at = Column(DateTime, server_default=func.now())


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id           = Column(Integer, primary_key=True, index=True)
    indicator    = Column(String(255), index=True)
    ioc_type     = Column(String(50))
    risk_level   = Column(String(50))
    risk_score   = Column(Integer)
    confidence   = Column(String(50))
    source       = Column(String(255))
    final_verdict = Column(String(50))
    is_favorite  = Column(Boolean, default=False)
    user_id      = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at   = Column(DateTime, server_default=func.now())

    user         = relationship("User", back_populates="scans")


class IPReputation(Base):
    __tablename__ = "ip_reputation"

    id            = Column(Integer, primary_key=True, index=True)
    ip            = Column(String(50), index=True)
    final_verdict = Column(String(50))
    country       = Column(String(50))
    data          = Column(JSON)
    created_at    = Column(DateTime, server_default=func.now())

class ActivityLog(Base):
    __tablename__ = "activity_logs"

    id          = Column(Integer, primary_key=True, index=True)
    ip          = Column(String(50))
    method      = Column(String(10))
    path        = Column(String(255))
    status_code = Column(Integer)
    duration_ms = Column(Integer)
    created_at  = Column(DateTime, server_default=func.now())


class ChatSession(Base):
    __tablename__ = "chat_sessions"

    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=False)
    title      = Column(String(255), default="Nouvelle conversation")
    created_at = Column(DateTime, server_default=func.now())

    user     = relationship("User", back_populates="sessions")
    messages = relationship(
        "ChatMessage", back_populates="session", cascade="all, delete-orphan"
    )


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id         = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("chat_sessions.id"), nullable=False)
    role       = Column(String(20), nullable=False)
    content    = Column(Text, nullable=False)
    created_at = Column(DateTime, server_default=func.now())

    session = relationship("ChatSession", back_populates="messages")
