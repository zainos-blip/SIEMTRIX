from fastapi import APIRouter, Depends, HTTPException
import httpx
from pydantic import BaseModel
from jwt_utils import get_current_admin_user
from config import settings
from db import verify_and_update_login
import asyncio

router = APIRouter(prefix="/api/v1", tags=["Attack Simulation"])

class AttackRequest(BaseModel):
    password: str

from fastapi import APIRouter, Depends, HTTPException, Request

@router.post("/run_attack_simulation")
async def run_attack_simulation(req: Request, request: AttackRequest, current_user: dict = Depends(get_current_admin_user)):
                       
    is_valid, _ = verify_and_update_login(current_user["username"], request.password)
    if not is_valid:
        raise HTTPException(status_code=403, detail="Invalid password for attack simulation")

                                                                                                
    dmz_token = req.headers.get("X-DMZ-Session-Token")
    
    if not dmz_token:
                                                                       
        try:
            async with httpx.AsyncClient() as client:
                login_resp = await client.post(
                    f"{settings.dmz_base_url}/api/login", 
                    params={"username": current_user["username"], "role": current_user["role"]}
                )
                if login_resp.status_code == 200:
                    dmz_token = login_resp.json().get("session_token")
        except Exception as e:
            print(f"Failed to login to DMZ for attack simulation fallback: {e}")
 
    if not dmz_token:
        raise HTTPException(status_code=500, detail="Could not obtain DMZ session token")

    from attack_simulation import run_attacks
    try:
                                                                                          
        jwt_token = req.headers.get("Authorization", "").replace("Bearer ", "") if req.headers.get("Authorization") else None
        
                                                                                                  
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(None, run_attacks, jwt_token, dmz_token)
        return results
    except Exception as e:
        print(f"Error in attack simulation: {e}")
        raise HTTPException(status_code=500, detail=str(e))
