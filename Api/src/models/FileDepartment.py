from sqlmodel import Field, SQLModel

class FileDepartment(SQLModel, table=True):
    __tablename__ = "file_department"
    file_uid: str | None = Field(default=None, foreign_key="file.uid", primary_key=True)
    department_id: int | None = Field(default=None, foreign_key="department.id", primary_key=True)
    


