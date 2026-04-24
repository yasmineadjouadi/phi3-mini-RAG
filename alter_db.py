from database.db import engine, Base
from database import models  # charge tous les modèles
from sqlalchemy import text

# Crée toutes les tables manquantes
Base.metadata.create_all(bind=engine)
print("✅ Tables créées")

# Ajoute les colonnes manquantes si pas encore là
with engine.connect() as conn:
    alterations = [
        "ALTER TABLE users ADD COLUMN langue VARCHAR(10) DEFAULT 'fr'",
        "ALTER TABLE users ADD COLUMN theme VARCHAR(10) DEFAULT 'dark'",
        "ALTER TABLE scan_history ADD COLUMN user_id INT NULL",
        "ALTER TABLE scan_history ADD COLUMN confidence VARCHAR(50) NULL",
        "ALTER TABLE scan_history ADD COLUMN source VARCHAR(255) NULL",
        "ALTER TABLE scan_history ADD COLUMN final_verdict VARCHAR(50) NULL",
        "ALTER TABLE scan_history ADD COLUMN is_favorite TINYINT(1) NOT NULL DEFAULT 0",
    ]
    for sql in alterations:
        try:
            conn.execute(text(sql))
            print(f"✅ {sql[:50]}...")
        except Exception as e:
            print(f"⚠️  déjà existant ou erreur : {e}")
    conn.commit()

print("✅ Done")