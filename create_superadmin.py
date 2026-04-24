from database.db import SessionLocal, Base, engine
from database import models  # ← charge tous les modèles dans la même Base
from services.auth_service import hash_password
from sqlalchemy import inspect

def create_superadmin():
    # Crée les tables manquantes
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    existing = db.query(models.User).filter(models.User.email == "cboussoura").first()
    if existing:
        print("✅ Superadmin cboussoura existe déjà.")
        db.close()
        return

    superadmin = models.User(
        email="cboussoura",
        password_hash=hash_password("Passw0rd@2o26"),
        role="superadmin",
        is_active=True
    )
    db.add(superadmin)
    db.commit()
    print("✅ Superadmin cboussoura créé avec succès.")
    db.close()

if __name__ == "__main__":
    create_superadmin()