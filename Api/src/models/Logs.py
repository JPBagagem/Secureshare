from sqlmodel import Field, SQLModel
from datetime import datetime

class Logs(SQLModel, table=True):
    __tablename__ = "logs"
    id: int  = Field(default=None, primary_key=True)
    action: str
    time_stamp: datetime
    description:str
    user_id: int = Field(foreign_key="user.id")
    previous_hash: str
    current_hash:str
    check_by: int | None = Field(foreign_key="user.id")
    check_at: datetime | None = None   
    signature: str | None = None       

class LogsCreate(SQLModel):
    action: str
    time_stamp: datetime
    description:str
    user_id: int 
    previous_hash: str
    current_hash:str
    check_by: int | None = None
    check_at: datetime | None = None
    signature: str | None = None
class LogsUpdate(SQLModel):
    action: str |  None = None
    time_stamp: datetime |  None = None
    description:str |  None = None
    user_id: int |  None = None
    previous_hash: str |  None = None
    current_hash:str |  None = None

    check_by: int | None = None
    check_at: datetime | None = None
    signature: str | None = None
    