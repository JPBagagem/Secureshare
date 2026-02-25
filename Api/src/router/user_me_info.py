from fastapi import APIRouter, HTTPException
from src.core.deps import SessionDep, CurrentUser
from src.services.UserService import UserService
from src.models.User import UserInfoResponse, UserInfoUpdate, User

router = APIRouter()
user_service = UserService()

@router.get("", response_model=UserInfoResponse)
async def get_user_info(current_user: CurrentUser, session: SessionDep):
    # Fetch full user to get last_login and other fields
    user = session.get(User, current_user.id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.post("", response_model=UserInfoResponse)
async def update_user_info(user_update: UserInfoUpdate, session: SessionDep, current_user: CurrentUser):

    # Fetch full user to update
    user = session.get(User, current_user.id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user_service.update_user_info(session=session, user=user, user_update=user_update)
