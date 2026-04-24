from fastapi import Request, HTTPException
from collections import defaultdict
import time

# stockage en mémoire : {ip: [timestamps]}
_requests = defaultdict(list)

WINDOW_SECONDS = 60
MAX_REQUESTS = 60  # max 60 requêtes par minute par IP


async def rate_limit_middleware(request: Request, call_next):
    ip = request.client.host
    now = time.time()

    # Nettoyer les anciennes requêtes
    _requests[ip] = [t for t in _requests[ip] if now - t < WINDOW_SECONDS]

    if len(_requests[ip]) >= MAX_REQUESTS:
        raise HTTPException(
            status_code=429,
            detail=f"Trop de requêtes — max {MAX_REQUESTS}/min. Réessaie dans {WINDOW_SECONDS}s."
        )

    _requests[ip].append(now)
    response = await call_next(request)
    return response