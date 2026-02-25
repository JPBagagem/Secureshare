from src.models.Logs import Logs
from fastapi import APIRouter,HTTPException,UploadFile, File, Form,Header
from src.core.deps import SessionDep,CurrentUser
from fastapi import Request as Req
from src.services.LogService import LogService
from fastapi.responses import FileResponse
import os
import base64

router = APIRouter()
log_service = LogService()

@router.get("/audit/log" )
async def get_logs( session: SessionDep, current_user: CurrentUser):
    logs,tampered = log_service.get_logs(session=session, user_id=current_user.id)
    if not logs:
        raise HTTPException(
            status_code=404,
            detail="Cant acess logs"
        )
    if(tampered):
        print("someone tampered with logs")
    print("\n\n\n\n")
    return {"Logs": logs,"Tampered":tampered}

@router.put("/audit/validate")
async def sign_log(log_id: int = Form(...), signature: str = Form(...), session: SessionDep = None, current_user: CurrentUser = None):
    """
    Sign a log entry after verifying the hash chain integrity.
    The signature should be created by signing the log's current_hash with the user's private key.
    """
    try:
        signature_bytes = base64.b64decode(signature)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Invalid signature format - must be base64 encoded"
        )
    
    result, error = log_service.sign_log(
        session=session,
        user_id=current_user.id,
        log_id=log_id,
        signed_object=signature_bytes
    )
    
    if error:
        raise HTTPException(
            status_code=400,
            detail=error
        )
    
    return {"message": "Log signed successfully", "log": result}

