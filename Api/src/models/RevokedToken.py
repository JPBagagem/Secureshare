from sqlmodel import Field, SQLModel
from datetime import datetime

class RevokedToken(SQLModel, table=True):
    __tablename__ = "revoked_tokens"
    
    id: int | None = Field(default=None, primary_key=True)
    token: str = Field(index=True, unique=True)
    expires_at: datetime = Field(index=True)
