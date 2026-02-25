from fastapi import APIRouter, HTTPException
from src.core.deps import SessionDep, CurrentUser
from src.services.UserService import UserService
from src.models.User import UserActivate, UserActivateResponse, UserLogin, LoginResponse
from src.models.RevokedToken import RevokedToken
from fastapi import Depends, status
from src.core.deps import oauth2_scheme
from src.core.security import ALGORITHM
import jwt
from datetime import datetime, timezone
from sqlmodel import text
from src.core.settings import settings


router = APIRouter()
user_service = UserService()

@router.post("/activate", response_model=UserActivateResponse)
async def activate_user(user_activate: UserActivate, session: SessionDep):
    user = user_service.activate_user(session=session, user_activate=user_activate)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid username or password")
    return user

@router.post("/login", response_model=LoginResponse)
async def login(user_login: UserLogin, session: SessionDep):
    token = user_service.login_user(session=session, user_login=user_login)
    if not token:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    return token

@router.post("/logout")
async def logout(user: CurrentUser, token: str = Depends(oauth2_scheme), session: SessionDep = None):
    try:

        # key_bytes = PUBLIC_KEY.public_bytes(
        #     encoding=serialization.Encoding.PEM,
        #     format=serialization.PublicFormat.SubjectPublicKeyInfo
        # )
        payload = jwt.decode(token, settings.PUBLIC_KEY, algorithms=[ALGORITHM])
        exp = payload.get("exp")
        
        if exp:
            expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
            
            # Cleanup expired tokens
            session.exec(
                text("DELETE FROM revoked_tokens WHERE expires_at < :current_time"),
                params={"current_time": datetime.now(timezone.utc)}
            )
            
            # Revoke current token
            revoked_token = RevokedToken(token=token, expires_at=expires_at)
            session.add(revoked_token)
            session.commit()
            
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return {"message": "Successfully logged out"}
