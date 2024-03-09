from typing import List, Optional, Union, Annotated
from fastapi import FastAPI, HTTPException
from sqlmodel import Session
from db import *

app = FastAPI()

@app.post('/create/note/')
async def create_note(note:Notes):
    with Session(engine) as session:
        session.add(note)
        session.commit()
        session.refresh(note)
        return note

 
@app.get('/note/{id}')
async def get_note(id:int):
    with Session(engine) as session:
        notes = session.get(Notes, id)
        if not notes:
            raise HTTPException(status_code=404, detail="ToDoNote not found")
        else:
            notes = session.exec(select(Notes)).all()
            return notes

@app.get('/read/note', response_model=List[Notes])
async def read_note():
    with Session(engine) as session:
        notes = session.exec(select(Notes)).all()
        return notes

@app.delete('/delete/note/{id}/')
async def delete_note(id:int):
    with Session(engine) as session:
        notes = session.get(Notes, id)
        if not notes:
            raise HTTPException(status_code=404, detail="ToDoNote not found")
        session.delete(notes)
        session.commit()
        return {"ok": True}
