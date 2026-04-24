from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "mysql+pymysql://root:Azerty%40%2F1@localhost:3306/threatintel")

engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def _mysql_column_exists(conn, table: str, column: str) -> bool:
    q = text(
        """
        SELECT COUNT(*) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = :t
          AND COLUMN_NAME = :c
        """
    )
    n = conn.execute(q, {"t": table, "c": column}).scalar()
    return int(n or 0) > 0


def _apply_mysql_schema_patches():
    """create_all() n’altère pas les tables existantes — ajoute les colonnes ORM si absentes."""
    if not str(engine.url).startswith("mysql"):
        return
    alters: list[tuple[str, str, str]] = [
        ("scan_history", "user_id", "ALTER TABLE scan_history ADD COLUMN user_id INT NULL"),
        ("scan_history", "confidence", "ALTER TABLE scan_history ADD COLUMN confidence VARCHAR(50) NULL"),
        ("scan_history", "source", "ALTER TABLE scan_history ADD COLUMN source VARCHAR(255) NULL"),
        ("scan_history", "final_verdict", "ALTER TABLE scan_history ADD COLUMN final_verdict VARCHAR(50) NULL"),
        ("scan_history", "is_favorite", "ALTER TABLE scan_history ADD COLUMN is_favorite TINYINT(1) NOT NULL DEFAULT 0"),
        ("users", "langue", "ALTER TABLE users ADD COLUMN langue VARCHAR(10) DEFAULT 'fr'"),
        ("users", "theme", "ALTER TABLE users ADD COLUMN theme VARCHAR(10) DEFAULT 'dark'"),
    ]
    with engine.begin() as conn:
        for table, col, ddl in alters:
            if _mysql_column_exists(conn, table, col):
                continue
            try:
                conn.execute(text(ddl))
                print(f"[init_db] Colonne ajoutée : {table}.{col}")
            except Exception as e:
                print(f"[init_db] Échec {table}.{col} : {e}")


def init_db():
    from database import models  # import relatif via package → même Base

    Base.metadata.create_all(bind=engine)
    _apply_mysql_schema_patches()