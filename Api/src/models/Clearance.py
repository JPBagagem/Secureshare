from sqlmodel import SQLModel, Field

class Clearance(SQLModel, table=True):
    __tablename__ = "clearance"
    id: int  = Field(default=None, primary_key=True)
    name: str = Field(sa_column_kwargs={"unique": True})




class ClearanceCreate(SQLModel):
    name: str


class ClearanceUpdate(SQLModel):
    name: str 

