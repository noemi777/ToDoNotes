from sqlalchemy import Boolean, Column, ForeignKey, Integer, String
from db import Base

class Notes(Base):
    __tablename__ = 'todonotes'

    id = Column(Integer, primary_key=True, index= True)
    title = Column(String, index=True)
    description = Column(String)
"""class Users(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True)
    full_name = Column(String)"""