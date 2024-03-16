from datetime import timedelta, datetime
from typing import Annotated, Optional
from fastapi import Depends, FastAPI, HTTPException,status, Header
from jose import JWTError, jwt
import models
from db import ALGORITHM, SECRET_KEY, engine, get_db
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware
from schemas import UserCreate, NotesBase, Token, TokenData, UserBase, Notes
from crud import create_access_token_user, get_password_hash, user_dependency, pwd_context, oauth2_scheme

app = FastAPI()


models.Base.metadata.create_all(bind=engine)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "PUT"],
    allow_headers=["*"],
)

# Dependency

db_dependency = Annotated[Session, Depends(get_db)]


@app.get("/")
def root():
    return "Hola, Mundo"


# Create user
@app.post("/create/user")
async def create_user_account(pwd: UserCreate, db: db_dependency):
    new_user = models.UserModel(
        email=pwd.email,
        nickname=pwd.nickname,
        full_name=pwd.full_name,
        hashed_password=get_password_hash(pwd.hashed_password),
        registered_at=datetime.now(),
        updated_at=datetime.now(),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    # Generet token for each new user
    access_token = create_access_token_user(
        new_user.email, new_user.id, timedelta(minutes=20)
    )
    return {"message": "New user as been created", "access_token": access_token}


@app.post("/token", response_model=Token)
async def login_for_access_token(credentials: TokenData, db: db_dependency):
    user = authenticate_user(credentials.email, credentials.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not validated"
        )
    token = create_access_token_user(user.email, user.id, timedelta(minutes=20))

    return {"access_token": token, "token_type": "bearer"}


def authenticate_user(email: str, password: str, db: db_dependency):
    user = db.query(models.UserModel).filter(models.UserModel.email == email).first()
    if not user:
        return False
    if not pwd_context.verify(password, user.hashed_password):
        return False
    return user



@app.get("/user/me", status_code=status.HTTP_200_OK)
async def user(user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication Failes")
    return {"User": user}

# Note by id
@app.get("/note/{note_id}")
async def get_note(note_id: int, db: db_dependency):
    result = db.query(models.Notes).filter(models.Notes.id == note_id).first()
    if not result:
        raise HTTPException(status_code=404, detail="ToDoNote not found")
    return result


#Crear una nota con un usuario logeado
@app.post("/notes/")
async def create_note_for_user(note: NotesBase, token: str = Depends(oauth2_scheme), db= Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print(payload)
        user_id: int = payload.get("id")
        print(user_id)
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid user"
            )

        db_note = models.Notes(
            title=note.title, description=note.description, user_id=user_id
        )
        db.add(db_note)
        db.commit()
        db.refresh(db_note)
        return db_note
    except jwt.JWTError:
        raise HTTPException( 
            status_code=status.HTTP_401_UNAUTHORIZED
        )

# Create note by user id
@app.post("/users/{user_id}/notes/")
async def create_item_for_user(user_id: int, note: NotesBase, db: db_dependency):
    db_note = models.Notes(
        title=note.title, description=note.description, user_id=user_id
    )
    db.add(db_note)
    db.commit()
    db.refresh(db_note)
    return db_note


# @app.get('/read/note')
# async def read_note(db:db_dependency):
#     all_note = db.query(models.Notes).all()
#     return all_note

# def decode_jwt(token: str) -> int:
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         user_id: int = payload.get("user_id")
#         if user_id is None:
#             raise HTTPException(status_code=400, detail="User ID not found in token")
#         return user_id
#     except JWTError:
#         raise HTTPException(status_code=401, detail="Invalid token") 


@app.get('/read/note')
async def read_note(authorization: Optional[str] = Header(None), db=Depends(get_db)):
    if authorization is None:
        raise HTTPException(status_code=401, detail="Authorization header missing")

    # Extract the token part from the Authorization header
    if(token.length > 1):
        token = authorization.split(" ")[1]
    print(token)

    # Decode the JWT token directly to get the user ID
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print(payload)
        user_id: int = payload.get("id")
        if user_id is None:
            raise HTTPException(status_code=400, detail="User ID not found in token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Fetch all tasks related to the user ID
    all_note = db.query(models.Notes).filter(models.Notes.user_id == user_id).all()
    return all_note


# Update notes by id
@app.put("/note/update/{note_id}")
async def update_note(note_id: int, note: NotesBase, db: db_dependency):
    update = db.query(models.Notes).filter(models.Notes.id == note_id).first()
    update.title = note.title
    update.description = note.description
    db.commit()
    db.refresh(update)
    return update


# Delete note by id
@app.delete("/delete/note/{note_id}/")
async def delete_note(note_id: int, db: db_dependency):
    note = db.query(models.Notes).filter(models.Notes.id == note_id).first()
    db.delete(note)
    db.commit()
    return {"Message": "Note deleted"}
