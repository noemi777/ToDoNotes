from pydantic import BaseModel,  EmailStr
from datetime import datetime


class Token(BaseModel):
    access_token: str
    token_type: str
    #email: str
    
class TokenData(BaseModel):
    email : str
    #scopes: list[str] = []

class NotesBase(BaseModel):
    title : str 
    description : str

class Notes(NotesBase):
    id: int
    user_id : int

class UserBase(BaseModel):
    email: EmailStr
    nickname: str
    full_name:str
    registered_at : datetime
    updated_at : datetime
    notes: list[Notes] = []

class UserCreate(UserBase):
    hashed_password: str
