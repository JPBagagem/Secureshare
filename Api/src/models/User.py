from sqlmodel import Field, SQLModel
from datetime import datetime, timezone
from src.models.RoleToken import RoleTokenResponse
from src.models.ClearanceToken import ClearanceTokenResponse


class User(SQLModel, table=True):
    __tablename__ = "user"
    id: int  = Field(default=None, primary_key=True)
    user_name: str = Field(sa_column_kwargs={"unique": True})
    blob: bytes | None = Field(default=None)
    hash_password:str = Field(default=None)
    salt: str | None = Field(default=None)
    assymetric_public_key:str | None = Field(default=None)
    is_activated: bool = Field(default=False)
    last_login: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserCreate(SQLModel):
    user_name: str

    
class UserCreatedResponse(UserCreate):
    id: int
    password: str

class UserActivate(SQLModel):
    user_name: str
    password: str
    one_time_password: str
    assymetric_public_key: str

class UserActivateResponse(SQLModel):
    id: int 
    user_name: str 
    hash_password: str
    assymetric_public_key: str
    last_login: datetime

class UserLogin(SQLModel):
    user_name: str
    password: str

class LoginResponse(SQLModel):
    user_id: int
    access_token: str
    role_tokens: dict[str, RoleTokenResponse] = {}
    clearance_tokens: list[ClearanceTokenResponse] = []

class UserVaultRequest(SQLModel):
    blob: str

class UserVaultResponse(SQLModel):
    blob: str | None = None

class UserInfoResponse(SQLModel):
    id: int
    user_name: str
    last_login: datetime

class UserInfoUpdate(SQLModel):
    user_name: str | None = None
    password: str | None = None

class PublicKeyResponse(SQLModel):
    assymetric_public_key: str | None = None

class FixtureLoginResponse(LoginResponse):
    private_key: str