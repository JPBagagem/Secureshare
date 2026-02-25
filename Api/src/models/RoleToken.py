from sqlmodel import Field, SQLModel
from datetime import datetime


class RoleToken(SQLModel, table=True):
    __tablename__ = "role_token"

    id: int  = Field(default=None, primary_key=True)

    user_id: int | None = Field(default=None,foreign_key="user.id")
    role_id: int | None = Field(default=None, foreign_key="role.id")
    department_id: int | None = Field(default=None, foreign_key="department.id")
    
    issued_at: datetime
    issued_by: int = Field(foreign_key="user.id")
    status: str = Field(default="ACTIVE")
    signature: str


class RoleTokenCreate(SQLModel):
    signature: str

class RoleTokenResponse(SQLModel):
    id: int
    user_id: int
    role_id: int
    department_id: int | None = None
    issued_at: datetime
    issued_by: int
    signature: str
