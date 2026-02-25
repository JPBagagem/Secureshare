from sqlmodel import Field, SQLModel
from datetime import datetime, timezone

class EncryptedFileKeys(SQLModel, table=True):
    __tablename__ = "encrypted_file_keys"

    id: int  = Field(default=None, primary_key=True)

    recipient_user_id: int | None = Field(default=None,foreign_key="user.id")
    file_uid: str | None = Field(default=None, foreign_key="file.uid")
    encrypted_key: str 
    created_at: datetime = Field(default_factory=lambda:datetime.now(timezone.utc))



class EncryptedFileKeysCreate(SQLModel):
    recipient_user_id: int
    file_uid: str 
    encrypted_key: str 
    created_at: datetime = Field(default_factory=lambda:datetime.now(timezone.utc))
