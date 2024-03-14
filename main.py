from datetime import timedelta, datetime
from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, status
from models import UserModel
import models
from db import engine, get_db
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from schemas import  UserCreate, NotesBase
from crud import create_access_token, get_password_hash, user_dependency, pwd_context


app = FastAPI()


models.Base.metadata.create_all(bind=engine)

#CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=['GET', 'POST', 'DELETE', 'PUT'],
    allow_headers=["*"],
)

#Dependency

db_dependency = Annotated[Session, Depends(get_db)]


@app.get('/')
def root():
    return 'Hola, Mundo'

#Create user
@app.post('/create/user')
async def create_user_account (pwd:UserCreate, db:db_dependency):
    new_user = models.UserModel(
        email = pwd.email,
        nickname = pwd.nickname,
        full_name=pwd.full_name,
        hashed_password = get_password_hash(pwd.hashed_password),
        registered_at = datetime.now(),
        updated_at = datetime.now()
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    #Generet token for each new user
    access_token = create_access_token(new_user.email, new_user.id, timedelta(minutes=20))
    return {'message': 'New user as been created', 'access_token': access_token}

"""@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Email o contraseña incorrectos")
    # Aquí podrías generar un token JWT para autenticación si lo deseas
    token = create_access_token(user.email, user.id, timedelta(minutes=20))
    return {"message": "Login exitoso"} """

@app.post('/login')
#async def login_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependency):
async def login(email: str, hashed_password: str, db:db_dependency):
    user = authenticate_user(email, hashed_password, db)
    #user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='User not validated')
    token = create_access_token(user.email, user.id, timedelta(minutes=20))
    return {"message": "Login exitoso",'access_token': token} 

def authenticate_user(email:str, hashed_password:str, db:db_dependency):
    user = db.query(UserModel).filter(UserModel.email == email).first()
    if not user:
        return False 
    if not pwd_context.verify(hashed_password, user.hashed_password):
        return False
    return user

@app.get('/user/me', status_code=status.HTTP_200_OK)
async def user(user:user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail='Authentication Failes')
    return {'User':user}

#Note by id
@app.get('/note/{note_id}')
async def get_note(note_id:int, db: db_dependency):
    result = db.query(models.Notes).filter(models.Notes.id==note_id).first()
    if not result:
        raise HTTPException(status_code=404, detail="ToDoNote not found")
    return result


#Create note by user id
@app.post("/users/{user_id}/notes/")
async def create_item_for_user(user_id: int, note:NotesBase, db:db_dependency):
    db_note = models.Notes(title=note.title, description=note.description, user_id=user_id)
    db.add(db_note)
    db.commit()
    db.refresh(db_note)
    return db_note
    

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
    return {"Message": 'Note deleted'}


