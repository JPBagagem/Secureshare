from sqlmodel import Field, SQLModel

class ClearanceDepartment(SQLModel, table=True):
    __tablename__ = "clearance_departments"
    clearance_token_id: int | None = Field(default=None,foreign_key="clearance_tokens.id", primary_key=True)
    department_id: int | None = Field(default=None, foreign_key="department.id", primary_key=True)
    


