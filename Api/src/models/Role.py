from sqlmodel import SQLModel, Field
from enum import Enum

class RoleType(str, Enum):
    ADMINISTRATOR = "ADMINISTRATOR"
    SECURITY_OFFICER = "SECURITY_OFFICER"
    TRUSTED_OFFICER = "TRUSTED_OFFICER"
    STANDARD_USER = "STANDARD_USER"
    AUDITOR = "AUDITOR"

class Role(SQLModel, table=True):
    __tablename__ = "role"
    id: int  = Field(default=None, primary_key=True)
    role: str = Field(sa_column_kwargs={"unique": True})
    description: str |None



class RoleCreate(SQLModel):
    role: str
    description: str |None

class RoleUpdate(SQLModel):
    role: str | None = None
    description: str  | None = None

