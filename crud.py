from datetime import timedelta, datetime, timezone
from typing import Annotated
from fastapi import Depends, HTTPException, status
from sqlmodel import Session
from models import UserModel
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from jose import JWTError, jwt
from db import SECRET_KEY, ALGORITHM, get_db


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated='auto')


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


"""def authenticate_user(username: str, hashed_password: str, db_session):
    user = db_session.query(UserModel).filter(UserModel.email == username).first()
  #  user = db_dependency.get(email)
    if not user:
        return False
    if not pwd_context.verify(hashed_password, user.hashed_password):
        return False
    return user"""



"""def authenticate_user(email:str, hashed_password:str, db:db_dependency):
    user = db.query(UserModel).filter(UserModel.email == email).first()
    if not user:
        return False 
    if not pwd_context.verify(hashed_password, user.hashed_password):
        return False
    return user"""
"""def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, "secret_key", algorithm="HS256")
    return encoded_jwt"""

def create_access_token(email:str, user_id:int, expires_delta: timedelta):
    enconde = {'sub': email, 'id': user_id}
    expires = datetime.now(timezone.utc) + expires_delta
    enconde.update({'exp':expires})
    return jwt.encode(enconde, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        user_id: int = payload.get('id')
        if email is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='User invalidated')
        return {'email': email, 'id': user_id}
    
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate user')
    

user_dependency = Annotated[Session, Depends(get_current_user)]