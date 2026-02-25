from sqlmodel import Field, SQLModel
from datetime import datetime, timezone
from enum import Enum

class TokenStatus(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"

class ClearanceTokens(SQLModel, table=True):
    __tablename__ = "clearance_tokens"
    
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", nullable=False)
    clearance_id: int =  Field(foreign_key="clearance.id", nullable=False)
    expired_at: datetime | None = Field(default=None)
    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    issued_by: int | None = Field(default=None, foreign_key="user.id")
    token_status: str = Field(default=TokenStatus.ACTIVE.value, max_length=20)
    signature: str = Field(max_length=500)

class ClearanceTokenRequest(SQLModel):
    token: str

class ClearanceTokensRead(SQLModel):
    id: int
    user_id: int
    clearance_id: int
    expired_at: datetime | None
    issued_at: datetime
    issued_by: int | None
    token_status: str
    signature: str

class ClearanceTokensUpdate(SQLModel):
    expired_at: datetime | None = None
    token_status: str | None = None

class ClearanceTokenResponse(ClearanceTokensRead):
    clearance_name: str
    departments: list[int] = []