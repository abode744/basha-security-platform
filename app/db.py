import os
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from .config import settings

class Base(DeclarativeBase):
    pass

db_url = os.environ.get("DATABASE_URL") or settings.database_url
connect_args = {'check_same_thread': False} if 'sqlite' in db_url else {}

try:
    engine = create_engine(db_url, pool_pre_ping=True, connect_args=connect_args)
    # Validate DBAPI import and test ping
    with engine.connect() as conn:
        pass
except Exception as e:
    # Graceful fallback to SQLite when PostgreSQL/psycopg is unavailable (e.g., local Windows testing)
    print(f"[*] Note: Primary database ({db_url}) unavailable or driver missing: {e}")
    print("[*] Automatically routing to local SQLite database (basha_local.db)")
    db_url = "sqlite:///./basha_local.db"
    connect_args = {'check_same_thread': False}
    engine = create_engine(db_url, pool_pre_ping=True, connect_args=connect_args)

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
