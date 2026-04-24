from fastapi import APIRouter, Query, Depends
from services.mail_service import check_mail_reputation
from services.auth_service import get_current_user

router = APIRouter(dependencies=[Depends(get_current_user)])

@router.get("/", summary="Mail Reputation Check")
def mail_route(email: str = Query(..., description="Email to check")):
    return check_mail_reputation(email)