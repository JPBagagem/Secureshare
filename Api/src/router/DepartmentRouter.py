from src.models.Department import Department ,DepartmentCreate
from fastapi import APIRouter,HTTPException,UploadFile, File, Form
from src.core.deps import SessionDep,CurrentUser
from fastapi import Request as Req
from src.services.DepartmentService import DepartmentService

router = APIRouter()
dep_service = DepartmentService()


@router.get("/departments/" )
async def get_dep( session: SessionDep,current_user: CurrentUser)->list[Department]:

    dep = dep_service.get_departments(session=session, user_id=current_user.id)
    if not dep:
        raise HTTPException(status_code=400, detail="You dont have permission or there are no deps")
    return dep




@router.delete("/departments/{deptId}" )
async def delet_dep( session: SessionDep,current_user: CurrentUser,deptId:int)->Department:

    dep = dep_service.delet_departments(session=session,dep_id=deptId, user_id=current_user.id)
    if not dep:
        raise HTTPException(status_code=404, detail="Error removing the dep")
    return dep


@router.post("/departments/" )
async def add_dep( session: SessionDep,current_user: CurrentUser,data:DepartmentCreate)->Department:

    dep = dep_service.add_department(
        session=session,
        data=data,
        user_id=current_user.id
    )
    
    if not dep:
        raise HTTPException(
            status_code=403,
            detail="Access denied or department already exists"
        )
    
    return dep
