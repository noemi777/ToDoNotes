from datetime import datetime
from typing import Optional, Union
from pydantic import BaseModel
from sqlmodel import *
from sqlalchemy import Boolean, Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

"""class Notes(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str = Field(index=True)
    description: str"""
    

URL_DATABASE = 'postgresql://postgres:Lr35ui+)@localhost:5432/todonotesdn'

engine = create_engine(URL_DATABASE)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
#sqlite_url = "sqlite:///db.sqlite"
#postgres_url= "postgresql://user:password@postgresserver/db"
#create engine
#engine = create_engine(sqlite_url, echo=True)

#SQLModel.metadata.create_all(engine)