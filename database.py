from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = "postgresql://root:uCT6YLlVUfyqHYqGeZRDtwJF1iX57Mog@dpg-cq04vj6ehbks73e6ruj0-a.oregon-postgres.render.com/users_vbaq"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
