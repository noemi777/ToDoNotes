from datetime import datetime
from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, func, DateTime
from db import Base
from sqlalchemy.orm import relationship
class UserModel(Base):
    __tablename__= 'users'

    id = Column(Integer, primary_key=True)
    email = Column(String,unique=True, index=True)
    username = Column(String)
    first_name = Column(String)
    last_name = Column(String)
    hashed_password = Column(String)
    is_activate = Column(Boolean, default=False)
    is_verified = Column(Boolean, default=False)
    verified_at = Column(DateTime, nullable=True, default=None)
    registered_at = Column(DateTime, nullable=True, default=None)
    updated_at = Column(DateTime, nullable=True, default=None, onupdate=datetime.now)
    created_at = Column(DateTime, nullable=True, server_default=func.now())
    todonotes = relationship('Notes', back_populates='user')


class Notes(Base):
    __tablename__ = 'todonotes'

    id = Column(Integer, primary_key=True, index= True)
    title = Column(String, index=True)
    description = Column(String)
    user_id = Column(Integer, ForeignKey('users.id'))

    user = relationship('UserModel', back_populates='todonotes')

