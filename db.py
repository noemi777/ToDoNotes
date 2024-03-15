from sqlmodel import *
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import os
from pathlib import Path
from dotenv import load_dotenv

# Enviroment
env_path = Path(".") / ".env"
load_dotenv(dotenv_path=env_path)

# Access DB
URL_DATABASE = str = os.getenv("URL_DATABASE")

engine = create_engine(URL_DATABASE)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Others access
SECRET_KEY = str = os.getenv("SECRET_KEY")
ALGORITHM = str = os.getenv("ALGORITHM")
