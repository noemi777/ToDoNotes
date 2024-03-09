from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel
from sqlmodel import Session
import models
from db import engine, SessionLocal
from sqlalchemy.orm import Session

app = FastAPI()
models.Base.metadata.create_all(bind=engine)


class NotesBase(BaseModel):
    title : str 
    description : str

#Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

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


