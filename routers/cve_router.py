from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from services.cve_service import get_cve_report
from services.auth_service import get_current_user

router = APIRouter(dependencies=[Depends(get_current_user)])

@router.get("/")
def cve_lookup(cve_id: str):
    if not cve_id:
        return JSONResponse({"error": "CVE ID manquant"}, status_code=400)
    result = get_cve_report(cve_id)
    if "error" in result:
        return JSONResponse(result, status_code=404)
    return result