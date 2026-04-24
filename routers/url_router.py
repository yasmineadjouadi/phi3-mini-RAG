from fastapi import APIRouter, Query, Depends
from services.url_service import get_url_report
from services.auth_service import get_current_user

router = APIRouter(dependencies=[Depends(get_current_user)])

@router.get("/")
def url_lookup(param: str = Query(..., description="URL to scan")):
    return get_url_report(param)