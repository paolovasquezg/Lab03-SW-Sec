from sqlmodel import SQLModel, Field, create_engine, Session, select
from typing import Optional

class Users(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str
    name: str
    age: int

DATABASE_URL = "postgresql://postgres:1234@localhost:5432/postgres"

engine = create_engine(DATABASE_URL, echo=True)

def init_db():
    SQLModel.metadata.create_all(engine)

    with Session(engine) as session:
        has_one = session.exec(select(Users).limit(1)).first()
        if not has_one:
            users = [
                Users(username="alice", name="Alice Johnson", age=28),
                Users(username="bob", name="Bob Smith", age=32),
                Users(username="carol", name="Carol Davis", age=25),
                Users(username="dave", name="Dave Wilson", age=40),
                Users(username="eve", name="Eve Martinez", age=22),
                Users(username="frank", name="Frank Brown", age=35),
                Users(username="grace", name="Grace Lee", age=27),
                Users(username="heidi", name="Heidi Clark", age=30),
                Users(username="ivan", name="Ivan Garcia", age=29),
                Users(username="judy", name="Judy Kim", age=26),
            ]
            session.add_all(users)
            session.commit()



