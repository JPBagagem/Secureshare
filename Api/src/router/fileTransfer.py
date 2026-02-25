from src.models.File import File as Fi
from fastapi import APIRouter,HTTPException,UploadFile, File, Form
from src.core.deps import SessionDep,CurrentUser
from src.services.FileService import FileService
from fastapi.responses import FileResponse
import os
import base64
import re
from src.core.deps import SessionDep, CurrentUser, CurrentUserClearance


router = APIRouter()
file_service = FileService()


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal and special character injection.
    """
    if not filename:
        return "unknown"
    filename = filename.replace('/', '').replace('\\', '').replace('\0', '')
    filename = filename.replace('\r', '').replace('\n', '')
    filename = re.sub(r'[^\w\s\-\.]', '', filename)
    filename = filename.strip().strip('.')
    return filename if filename else "unknown"



@router.post("/transfers/")
async def add_transfer( session: SessionDep,
                         current_user: CurrentUser,
                         user_clearance: CurrentUserClearance,
                        clearance_level:str =Form(...),
                        aes_iv: str = Form(...),
                        aes_tag: str = Form(...),
                       encrypted_aes_key: str | None = Form(default=None),
                         file: UploadFile = File(...),
                         reason:str = Form(default=""),
                         is_private:bool = Form(default=True),
                         department_list:str = Form(default="")):
    
    # parse to base 64
    iv_bytes =aes_iv
    tag_bytes = aes_tag
    encrypted_key_bytes = None
    print(user_clearance)
    print("\n\n\n")
    if is_private and encrypted_aes_key:
        encrypted_key_bytes = base64.b64decode(encrypted_aes_key)

    if department_list:
        department_list = [int(d.strip()) for d in department_list.split(",") if d.strip()]
    else:
        department_list = []
    file_data = await file.read()
    file_n = sanitize_filename(file.filename)
    try:
        result = file_service.upload_file(session=session, user_id=current_user.id,file_name=file_n,is_privat=is_private,user_clearance=user_clearance,file_data=file_data,department_list=department_list,iv_bytes=iv_bytes,tag_bytes=tag_bytes,encrypted_key_bytes=encrypted_key_bytes,reason=reason, clearance_level=clearance_level)
        print("\n\n\n\n\n")
        if not result:
             raise HTTPException(status_code=400, detail="L")
        print(result)
        print("\n\n\n\n\n")
        file_info, uid = result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error doing the post {e}")
    return file_info

@router.post("/transfers/share/")
async def transfer_share( session: SessionDep,
                        current_user: CurrentUser,
                        file_uid: str = Form(...),
                        user_share_id: int = Form(...),
                        encrypted_aes_key: str = Form(...)):
    

    encrypted_key_bytes = base64.b64decode(encrypted_aes_key)
    share = file_service.share_file(session=session, owner_id=current_user.id,file_uid=file_uid,user_share_id=user_share_id,encrypted_key_bytes=encrypted_key_bytes)
    if not share:
        raise HTTPException(status_code=400, detail="Error doing the post")
    return share
    

@router.get("/transfers/" )
async def get_file( session: SessionDep, current_user: CurrentUser)->list[Fi]:
    files = file_service.get_file(session=session, user_id=current_user.id)
    return files


@router.get("/transfers/{file_uid}" )
async def get_single_file( session: SessionDep, current_user: CurrentUser, file_uid: str):
    files = file_service.get_one_file(session=session, user_id=current_user.id, file_uid=file_uid)
    if not files:
        raise HTTPException(
            status_code=404,
            detail="File doesn't exist or you don't have permission"
        )
    print(files)

    return files

@router.get("/download/{file_uid}" )
async def download_file( session: SessionDep, current_user: CurrentUser, file_uid: str, user_clearance: CurrentUserClearance, reason: str | None = Form(default="")):

    print(user_clearance)
    print("\n\n\n\n")
    result = file_service.download_file(session=session, file_uid=file_uid, user_id=current_user.id, user_clearance=user_clearance, reason=reason)
    if not result:
        raise HTTPException(
            status_code=404,
            detail="File doesn't exist or you don't have permission"
        )
    file_name, file_path, encrypted_key, iv_bytes, tag_bytes = result

    if not os.path.exists(file_path):
        raise HTTPException(
            status_code=404,
            detail="File not found on server"
        )

    response = FileResponse(
        path=file_path,
        media_type="application/octet-stream",
        filename=file_name
    )

    response.headers["X-Encrypted-Key"] = encrypted_key if encrypted_key else ""
    response.headers["X-IV"] = iv_bytes
    response.headers["X-Tag"] = tag_bytes
    response.headers["X-FileName"] = file_name
    print(response)
    return response


@router.delete("/transfers/{transfer_uid}" )
async def delete_file( session: SessionDep, current_user: CurrentUser, transfer_uid: str):

    file = file_service.delete_file(session=session, transfer_uid=transfer_uid, user_id=current_user.id)
    if not file:
        raise HTTPException(
            status_code=404,
            detail="File doesn't exist or you don't have permission"
        )

    return file


