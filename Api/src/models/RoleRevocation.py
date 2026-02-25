from sqlmodel import Field, SQLModel
from datetime import datetime

class RoleRevocation(SQLModel, table=True):
    __tablename__ = "role_revocation"
    revoked_by: int | None = Field(default=None,foreign_key="user.id", primary_key=True)
    role_token: int | None = Field(default=None, primary_key=True, foreign_key="role_token.id")
    
    revoked_at: datetime

    signature: str


class RoleRevocationCreate(SQLModel):
    revoked_by: int
    role_token: int
    revoked_at: datetime
    signature: str

class RoleRevocationRequest(SQLModel):
    signature: str
    revoked_at: datetime

class RoleRevocationResponse(SQLModel):
    revoked_by: int
    role_token: int
    revoked_at: datetime
    signature: str
