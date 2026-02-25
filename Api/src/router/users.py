from fastapi import APIRouter
from src.core.deps import SessionDep, CurrentUser, CurrentUserRole
from src.services.UserService import UserService
from src.models.User import User, UserCreate, UserCreatedResponse, UserVaultRequest, UserVaultResponse
from src.models.RoleToken import RoleTokenCreate, RoleTokenResponse
from src.models.RoleRevocation import RoleRevocationRequest, RoleRevocationResponse
from src.models.ClearanceToken import ClearanceTokenRequest, ClearanceTokenResponse
from src.models.ClearanceRevocations import ClearanceRevocationsRead
from src.models.Role import RoleType
from fastapi import HTTPException
import base64

router = APIRouter()
user_service = UserService()

@router.post("", response_model=UserCreatedResponse, status_code=201)
async def create_user(user: UserCreate, session: SessionDep, current_user: CurrentUser, role: CurrentUserRole):
    print("DEBUG: Creating user: ", role, flush=True)
    if role != RoleType.ADMINISTRATOR and role != RoleType.SECURITY_OFFICER:
        raise HTTPException(status_code=403, detail="Not authorized to create users")
        
    return user_service.create_user(session=session, user_create=user)

@router.get("", response_model=list[User])
async def get_users(session: SessionDep, current_user: CurrentUser,  role: CurrentUserRole):

    if role != RoleType.ADMINISTRATOR and role != RoleType.SECURITY_OFFICER :
        raise HTTPException(status_code=403, detail="Not authorized to get users")
    users = user_service.get_users(session=session)
    print(users)
    for user in users:
        if user.blob:
            user.blob = base64.b64encode(user.blob).decode()
    return users


@router.get("/{user_id}/key")
async def get_assymetric_key(session: SessionDep,user_id:int):
    return user_service.get_assymetric(session=session,user_id=user_id)


@router.put("/me/vault")
async def update_vault(vault_request: UserVaultRequest, session: SessionDep, current_user: CurrentUser):
    
    # Fetch full user to get blob
    user = session.get(User, current_user.id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    user_service.update_vault(session=session, user=user, blob=base64.b64decode(vault_request.blob))
    return {"message": "Vault updated"}

@router.get("/me/vault", response_model=UserVaultResponse)
async def get_vault(current_user: CurrentUser, session: SessionDep):
    # Fetch full user to get blob
    user = session.get(User, current_user.id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.blob:

        return UserVaultResponse(blob=base64.b64encode(user.blob).decode())
    return UserVaultResponse(blob=None)

@router.put("/{user_id}/role", response_model=RoleTokenResponse)
async def add_role(user_id: int, role_token: RoleTokenCreate, session: SessionDep, current_user: CurrentUser, role: CurrentUserRole):
    
    if role != RoleType.ADMINISTRATOR and role != RoleType.SECURITY_OFFICER:
        raise HTTPException(status_code=403, detail="Not authorized to assign roles")

    return user_service.add_role_token(session=session, user_id=user_id, role_token_create=role_token, granter_id=current_user.id)

@router.put("/{user_id}/revoke/{token_id}", response_model=RoleRevocationResponse | ClearanceRevocationsRead)
async def revoke_role(user_id: int, token_id: int, revocation_request: RoleRevocationRequest, session: SessionDep, current_user: CurrentUser, role: CurrentUserRole):
    
    if role != RoleType.SECURITY_OFFICER:
        raise HTTPException(status_code=403, detail="Not authorized to revoke roles")

    return user_service.revoke_token(session=session, user_id=user_id, token_id=token_id, revocation_request=revocation_request, revoker_id=current_user.id)



@router.delete("/{user_id}", status_code=204)
async def delete_user(user_id: int, session: SessionDep, current_user: CurrentUser, role: CurrentUserRole):
    if role != RoleType.ADMINISTRATOR:
        raise HTTPException(status_code=403, detail="Not authorized to delete users")
        
    user_service.delete_user(session=session, user_id=user_id)

@router.get("/{user_id}/clearance", response_model=list[ClearanceTokenResponse])
async def get_clearance(user_id: int, session: SessionDep, current_user: CurrentUser, role: CurrentUserRole):
    
    if current_user.id != user_id and role != RoleType.SECURITY_OFFICER:
        raise HTTPException(status_code=403, detail="Not authorized to get clearance tokens")
    
    if role == RoleType.SECURITY_OFFICER:
        return user_service.get_clearance_tokens(session=session, user_id=user_id)

    return user_service.get_clearance_tokens(session=session, user_id=user_id)

@router.put("/{user_id}/clearance", response_model=ClearanceTokenResponse)
async def add_clearance(user_id: int, clearance_token: ClearanceTokenRequest, session: SessionDep, current_user: CurrentUser, role: CurrentUserRole):
    
    if role != RoleType.SECURITY_OFFICER:
        raise HTTPException(status_code=403, detail="Not authorized to issue clearance tokens")

    return user_service.add_clearance_token(session=session, user_id=user_id, token_request=clearance_token, granter_id=current_user.id)
