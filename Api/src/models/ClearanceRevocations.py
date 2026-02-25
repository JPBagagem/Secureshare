from sqlmodel import Field, SQLModel
from datetime import datetime, timezone

class ClearanceRevocations(SQLModel, table=True):
    __tablename__ = "clearance_revocations"
    
    id: int | None = Field(default=None, primary_key=True)
    clearance_token_id: int = Field(foreign_key="clearance_tokens.id", nullable=False, index=True)
    revoked_by: int = Field(foreign_key="user.id", nullable=False)
    revoked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
    reason: str | None = Field(default=None)
    signature: str = Field(nullable=False)

class ClearanceRevocationsCreate(SQLModel):
    clearance_token_id: int
    revoked_by: int
    reason: str | None = None
    signature: str

class ClearanceRevocationsRead(SQLModel):
    id: int
    clearance_token_id: int
    revoked_by: int
    revoked_at: datetime
    reason: str | None
    signature: str

class ClearanceRevocationsUpdate(SQLModel):
    reason: str | None = None