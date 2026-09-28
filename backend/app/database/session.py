"""
Database connection and session management.
Supports PostgreSQL with transparent SQLite fallback for seamless local execution.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv

load_dotenv()

# Check environment for PostgreSQL URL or fallback to local SQLite
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./network_security.db")

# SQLite needs check_same_thread=False
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL, connect_args={"check_same_thread": False}
    )
else:
    # PostgreSQL configuration
    engine = create_engine(
        DATABASE_URL, pool_pre_ping=True, pool_size=10, max_overflow=20
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    """FastAPI Dependency for database session lifecycle"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
