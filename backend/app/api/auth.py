"""
Authentication & User Profile API Endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.models.models import User, AuditLog
from app.schemas.schemas import UserRegister, UserLogin, TokenResponse, UserOut
from app.services.auth_service import (
    verify_password,
    get_password_hash,
    create_access_token,
    get_current_user
)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

@router.post("/register", response_model=TokenResponse)
def register_user(req: UserRegister, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == req.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email address is already registered"
        )
    
    # First user is Admin, others follow req.role
    user_count = db.query(User).count()
    role = "Admin" if user_count == 0 else (req.role or "Security Analyst")
    
    new_user = User(
        email=req.email,
        hashed_password=get_password_hash(req.password),
        full_name=req.full_name,
        role=role
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Log action
    audit = AuditLog(
        user_id=new_user.id,
        action="USER_REGISTRATION",
        details=f"User {new_user.email} registered with role {new_user.role}"
    )
    db.add(audit)
    db.commit()

    token = create_access_token(data={"sub": new_user.email, "role": new_user.role})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": new_user.id,
            "email": new_user.email,
            "full_name": new_user.full_name,
            "role": new_user.role
        }
    }

@router.post("/login", response_model=TokenResponse)
def login_user(req: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated"
        )

    # Log action
    audit = AuditLog(
        user_id=user.id,
        action="USER_LOGIN",
        details=f"User {user.email} logged into SOC Dashboard"
    )
    db.add(audit)
    db.commit()

    token = create_access_token(data={"sub": user.email, "role": user.role})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role
        }
    }

@router.get("/me", response_model=UserOut)
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    return current_user
