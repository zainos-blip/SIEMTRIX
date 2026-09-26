from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from jwt_utils import get_current_admin_user
import db

router = APIRouter(prefix="/api/v1/users", tags=["Users"])

class UserCreate(BaseModel):
    username: str
    password: str
    role: str

class UserUpdate(BaseModel):
    password: Optional[str] = None
    role: Optional[str] = None

@router.get("")
async def get_users(current_user: dict = Depends(get_current_admin_user)):
    return db.get_all_users()

@router.post("")
async def create_user(user: UserCreate, current_user: dict = Depends(get_current_admin_user)):
    if user.role not in ["admin", "user"]:
        raise HTTPException(status_code=400, detail="Role must be admin or user")
    
    success = db.create_user(user.username, user.password, user.role)
    if not success:
        raise HTTPException(status_code=400, detail="User already exists")
    return {"status": "success", "message": "User created"}

@router.put("/{username}")
async def update_user(username: str, user_update: UserUpdate, current_user: dict = Depends(get_current_admin_user)):
    user_db = db.get_user_from_db(username)
    if not user_db:
        raise HTTPException(status_code=404, detail="User not found")
        
    updated = False
    if user_update.role:
        if user_update.role not in ["admin", "user"]:
            raise HTTPException(status_code=400, detail="Role must be admin or user")
        db.update_user_role(username, user_update.role)
        updated = True
        
    if user_update.password:
        db.update_user_password(username, user_update.password)
        updated = True
        
    if not updated:
        raise HTTPException(status_code=400, detail="No updates provided")
        
    return {"status": "success", "message": "User updated"}

@router.delete("/{username}")
async def delete_user(username: str, current_user: dict = Depends(get_current_admin_user)):
    if username == current_user["username"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
        
    success = db.delete_user(username)
    if not success:
        raise HTTPException(status_code=404, detail="User not found")
    return {"status": "success", "message": "User deleted"}
