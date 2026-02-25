from sqlmodel import Field, SQLModel
from datetime import datetime
import uuid

def generate_uid() -> str:
    """Generate a unique, unguessable identifier."""
    return str(uuid.uuid4())

class File(SQLModel, table=True):
    __tablename__ = "file"
    uid: str = Field(default_factory=generate_uid, primary_key=True)
    file_name:str 
    clearance_id: int =Field(foreign_key="clearance.id")
    reference_to_file: str = Field(sa_column_kwargs={"unique": True})
    symetric_key_encrypted: str |  None = None
    tag_bytes:str
    iv_bytes:str
    expire_at:datetime
    user_id: int = Field(foreign_key="user.id")
    is_private:bool

class FileCreate(SQLModel):
    file_name:str
    clearance_id: int 
    reference_to_file: str
    expire_at:datetime
    user_id: int 
    is_private:bool
    symetric_key_encrypted: str |  None = None
    tag_bytes:str
    iv_bytes:str


class FileUpdate(SQLModel):
    file_name:str | None=None
    clearance_id: int  |  None = None
    reference_to_file: str |  None = None
    expire_at:datetime |  None = None
    is_private:bool |  None = None
 


    