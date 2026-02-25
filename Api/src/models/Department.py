from sqlmodel import SQLModel, Field
from datetime import datetime
class Department(SQLModel, table=True):
    __tablename__ = "department"
    id: int  = Field(default=None, primary_key=True)
    name: str = Field(sa_column_kwargs={"unique": True})
    created_at: datetime
    created_by: int =Field(foreign_key="user.id")


class DepartmentCreate(SQLModel):
    name: str 
    created_at: datetime | None =None
    created_by: int  | None =None

class DepartmentnUpdate(SQLModel):
    name: str 

