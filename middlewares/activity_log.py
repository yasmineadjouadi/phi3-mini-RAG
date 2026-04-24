from fastapi import Request
from database.db import SessionLocal
from database.models import ActivityLog
import time


async def activity_log_middleware(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    duration = round((time.time() - start) * 1000)  # en ms

    # Logger seulement les routes API importantes
    path = request.url.path
    if any(path.startswith(p) for p in ["/ioc", "/hash", "/ip", "/domain", "/url", "/mail", "/cve"]):
        try:
            db = SessionLocal()
            log = ActivityLog(
                ip=request.client.host,
                method=request.method,
                path=path,
                status_code=response.status_code,
                duration_ms=duration,
            )
            db.add(log)
            db.commit()
            db.close()
        except Exception as e:
            print(f"[LOG] Erreur : {e}")

    return response