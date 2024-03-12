from datetime import timedelta, datetime, timezone
from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, Security, status
from pydantic import BaseModel, EmailStr, ValidationError
from models import UserModel, Notes
import models
from db import engine, SessionLocal, get_db
#from routes import router as user_router
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, SecurityScopes
from passlib.context import CryptContext
from jose import JWTError, jwt
SECRET_KEY = 'kkaskdj939oppa023101203pas91037ad53oak023lsa9342'
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class Token(BaseModel):
    access_token: str
    token_type: str
class TokenData(BaseModel):
    username: str 
    scopes: list[str] = []

class NotesBase(BaseModel):
    title : str 
    description : str

class Notes(NotesBase):
    id: int
    user_id : int

class UserBase(BaseModel):
    email: EmailStr
    username: str
    first_name:str
    last_name : str
    is_activate : bool
    is_verified : bool
    registered_at : datetime
    updated_at : datetime
    notes: list[Notes] = []

class UserCreate(UserBase):
    hashed_password: str


app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

models.Base.metadata.create_all(bind=engine)

#Dependency

db_dependency = Annotated[Session, Depends(get_db)]

#Funcionando
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)
#Funcionando
def get_password_hash(password):
    return pwd_context.hash(password)
#En prueba
def get_user(email:str, db:Session):
    user = db.query(UserModel).filter(UserModel.email == email).first()
    return user
#EN prueba 
def authenticate_user(db:Session, email:str, password:str):
    #user = db.query(models.UserModel).filter(models.UserModel.username==username).first() 
    user = get_user(email=email, db=db)
    print(user)
    if not user:
        raise HTTPException(status_code=401, detail='Not avalible', headers={"WWW-Authenticate": "Bearer"})
    if not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail='Not avalible', headers={"WWW-Authenticate": "Bearer"})
    return user
#En prueba
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
#En prueba
def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
#En prueba 
async def get_current_user(
        security_scopes: SecurityScopes, token: Annotated[str, Depends(oauth2_scheme)], db: Session= Depends(get_db)
):
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else: 
        authenticate_value= 'Bearer'
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": authenticate_value},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_scopes = payload.get("scopes", [])
        token_data = TokenData(scopes=token_scopes, username=username)
    except (JWTError, ValidationError):
        raise credentials_exception
    user = get_user(db=db, username=token_data.username)
    if user is None:
        raise credentials_exception
    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": authenticate_value},
            )
    return user
#En prueba
async def get_current_active_user(
    current_user: Annotated[UserBase, Security(get_current_user, scopes=["me"])]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

#CREATE USERS

@app.get('/')
def root():
    return 'Hola, Mundo'

#Create user
@app.post('/create/user')
async def create_user_account (pwd:UserCreate,email:str, db:db_dependency):
    email = db.query(models.UserModel).filter(models.UserModel.email == email).first()
    if email:
        raise HTTPException(status_code=422, detail='Email exists')
    #user =  db.query(models.UserModel).filter(models.UserModel.email == email).first()
    new_user = models.UserModel(
        email = pwd.email,
        username = pwd.username,
        first_name=pwd.first_name,
        last_name =pwd.last_name,
        hashed_password = get_password_hash(pwd.hashed_password),
        is_activate = False,
        is_verified = False,
        registered_at = datetime.now(),
        updated_at = datetime.now()
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.get("/users/me/", response_model=UserBase)
async def read_users_me(
    current_user: Annotated[UserBase, Depends(get_current_active_user)]
):
    return current_user


#Note by id
@app.get('/note/{note_id}')
async def get_note(note_id:int, db: db_dependency):
    result = db.query(models.Notes).filter(models.Notes.id==note_id).first()
    if not result:
        raise HTTPException(status_code=404, detail="ToDoNote not found")
    return result

#All notes
@app.get('/read/note')
async def read_note(db:db_dependency):
    all_note = db.query(models.Notes).all()
    return all_note

#Create note
@app.post('/create/notes/')
async def create_notes(note: NotesBase, db: db_dependency):
    db_notes = models.Notes(title=note.title,description=note.description )
    db.add(db_notes)
    db.commit()
    db.refresh(db_notes)
    return db_notes

#Update notes by id

@app.put('/note/update/{note_id}')
async def update_note(note_id:int, note:NotesBase, db:db_dependency):
    update = db.query(models.Notes).filter(models.Notes.id==note_id).first() 
    update.title = note.title
    update.description = note.description
    db.commit()
    db.refresh(update)
    return update

#Delete note by id
@app.delete('/delete/note/{note_id}/')
async def delete_note(note_id:int, db:db_dependency):
    note = db.query(models.Notes).filter(models.Notes.id==note_id).first()
    db.delete(note)
    db.commit()
    return {"ok": True}


