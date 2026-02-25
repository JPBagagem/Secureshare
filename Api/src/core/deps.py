from collections.abc import Generator
from typing import Annotated
from fastapi import Depends, Header
from sqlmodel import Session

from src.core.db import engine
from fastapi.security import OAuth2PasswordBearer
import jwt
from fastapi import HTTPException, status
from src.core.security import ALGORITHM
from src.models.User import User
from src.models.RevokedToken import RevokedToken
from sqlmodel import select
from src.models.Role import Role
from src.models.RoleToken import RoleToken
from src.models.ClearanceToken import ClearanceTokens, TokenStatus
from src.core.settings import settings

def get_db() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_db)]

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], session: SessionDep, key=None) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not key:
        key = settings.PUBLIC_KEY
    try:
        payload = jwt.decode(token, key.encode(), algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    
    user_id = payload.get("id")
    if user_id is None:
        raise credentials_exception

    # Construct user from token data without DB query
    user = User(id=user_id, user_name=username)
    
    # Check if token is revoked
    revoked_token = session.exec(select(RevokedToken).where(RevokedToken.token == token)).first()
    if revoked_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user

async def get_current_user_role(
    user: Annotated[User, Depends(get_current_user)], 
    session: SessionDep,
    x_role_token: Annotated[str | None, Header()] = None
) -> str | None:
    try:
        if not x_role_token:
            return None

        try:
            # 1. Decode without verification to get issuer
            unverified_payload = jwt.decode(x_role_token, options={"verify_signature": False})
            issuer_id = unverified_payload.get("iss")
            
            if not issuer_id:
                return None
                
            # 2. Get issuer's public key
            issuer = session.get(User, int(issuer_id))
            if not issuer or not issuer.assymetric_public_key:
                return None
                
            # 3. Verify signature
            payload = jwt.decode(x_role_token, issuer.assymetric_public_key, algorithms=[ALGORITHM])
            
            # 4. Verify subject matches current user
            if payload.get("sub") != str(user.id):
                return None
                
        except (jwt.PyJWTError, ValueError) as e:
            pass

        # 5. Verify the role token exists in DB (revocation check)
        role_token = session.exec(
            select(RoleToken).where(RoleToken.signature == x_role_token, RoleToken.user_id == user.id)
        ).first()
        
        if not role_token:
            return None
            
        # Get the role name
        role = session.get(Role, role_token.role_id)
        if not role:
            return None
            
        return role.role
    except Exception as e:
        print(f"CRITICAL ERROR in get_current_user_role: {e}", flush=True)
        import traceback
        traceback.print_exc()
        return None

async def get_current_user_clearance(
    user: Annotated[User, Depends(get_current_user)], 
    session: SessionDep,
    x_clearance_token: Annotated[str | None, Header()] = None
) -> str | None:
    
    if not x_clearance_token:
        return None

    try:
        # 1. Decode without verification to get issuer
        unverified_payload = jwt.decode(x_clearance_token, options={"verify_signature": False})
        issuer_id = unverified_payload.get("iss")
        
        if not issuer_id:
            return None
            
        # 2. Get issuer's public key
        issuer = session.get(User, int(issuer_id))
        if not issuer or not issuer.assymetric_public_key:
            return None
            
        # 3. Verify signature
        payload = jwt.decode(x_clearance_token, issuer.assymetric_public_key, algorithms=[ALGORITHM])
        
        # 4. Verify subject matches current user
        if payload.get("sub") != str(user.id):
            return None
            
    except (jwt.PyJWTError, ValueError) as e:
        return None

    # 6. Verify the clearance token exists in DB (revocation check)
    
    clearance_token = session.exec(
        select(ClearanceTokens).where(ClearanceTokens.signature == x_clearance_token, ClearanceTokens.user_id == user.id)
    ).first()
    
    if not clearance_token:
        return None
        
    if clearance_token.token_status != TokenStatus.ACTIVE.value:
        return None
        
    return clearance_token

CurrentUser = Annotated[User, Depends(get_current_user)]
CurrentUserRole = Annotated[str | None, Depends(get_current_user_role)]
CurrentUserClearance = Annotated[ClearanceTokens | None, Depends(get_current_user_clearance)]