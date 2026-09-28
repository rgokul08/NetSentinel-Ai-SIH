"""
Database connection and session management.
Supports PostgreSQL with transparent SQLite fallback for seamless local execution.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv

load_dotenv()

# Vercel and other serverless runtimes only allow writing to /tmp.
IS_SERVERLESS = bool(os.getenv("VERCEL"))

# Check environment for PostgreSQL URL or fallback to local SQLite
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./network_security.db")

if DATABASE_URL.startswith("sqlite"):
    # The deployment bundle is read-only on serverless runtimes, so keep the
    # fallback database in /tmp there (per-instance, wiped on new instances).
    if IS_SERVERLESS and DATABASE_URL.startswith("sqlite:///./"):
        DATABASE_URL = "sqlite:////tmp/network_security.db"
    engine = create_engine(
        DATABASE_URL, connect_args={"check_same_thread": False}
    )
else:
    # PostgreSQL configuration (smaller pool per instance on serverless)
    engine_kwargs = {"pool_pre_ping": True}
    if IS_SERVERLESS:
        engine_kwargs.update(pool_size=5, max_overflow=5, pool_recycle=1800)
    else:
        engine_kwargs.update(pool_size=10, max_overflow=20)
    engine = create_engine(DATABASE_URL, **engine_kwargs)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    """FastAPI Dependency for database session lifecycle"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
