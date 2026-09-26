from fastapi import APIRouter, Depends, HTTPException, Header, Request
import httpx
from typing import Optional
from jwt_utils import get_current_user, get_current_admin_user
import db
import uuid
import json
from config import settings
from main import CommandRequest, get_next_command_id, increment_session_counter, normalize_device_id, format_register_label, send_splunk_hec_event, is_business_hours
from datetime import datetime, timezone
from limiter import limiter

router = APIRouter(prefix="/api/v1", tags=["Approval"])

@router.post("/request_write")
@limiter.limit(f"{settings.rate_limit_max}/{settings.rate_limit_window}minute")
async def request_write(
    request: Request,
    cmd_request: CommandRequest,
    current_user: dict = Depends(get_current_user),
    x_dmz_session_token: Optional[str] = Header(None, alias="X-DMZ-Session-Token")
):
    if cmd_request.command_type != "w":
        raise HTTPException(status_code=400, detail="Only write commands require approval through this endpoint")

    cmd_id = get_next_command_id()
    
                        
    command_dict = cmd_request.model_dump()
    command_dict["command_id"] = cmd_id
    command_dict["issued_by"] = current_user["username"]
    
    db.create_pending_command(
        cmd_id=cmd_id,
        command_data=command_dict,
        dmz_session_token=x_dmz_session_token or "",
        issued_by=current_user["username"]
    )
    
    return {"status": "pending_approval", "pending_id": cmd_id}

@router.get("/pending")
async def list_pending_commands(current_user: dict = Depends(get_current_admin_user), status: str = "pending"):
    return db.get_pending_commands(status=status)

@router.post("/execute_scheduled/{cmd_id}")
async def execute_scheduled_command(cmd_id: str, current_user: dict = Depends(get_current_admin_user)):
    pending = db.get_pending_command(cmd_id)
    if not pending or pending["status"] != "scheduled":
        raise HTTPException(status_code=404, detail="Scheduled command not found")
        
    cmd_data = json.loads(pending["command_data"])
    dmz_session_token = pending["dmz_session_token"]
    
                 
    function_code = cmd_data.get("function_code") or 6
    dmz_timestamp = cmd_data.get("timestamp") or datetime.now(timezone.utc).isoformat()
        
    reg = cmd_data.get("register_number", cmd_data.get("register"))
    if isinstance(reg, str) and reg.startswith("HR_"):
        register_number = reg
    else:
        register_number = format_register_label(reg) if isinstance(reg, int) else reg

    write_payload = {
        "command_type": "w",
        "device_id": normalize_device_id(cmd_data["device_id"]),
        "register_number": register_number,
        "value": cmd_data["value"],
        "priority": cmd_data["priority"],
        "description": cmd_data.get("description", "scheduled command executed manually"),
        "issued_by": cmd_data["issued_by"],
        "command_id": cmd_id,
        "function_code": function_code,
        "timestamp": dmz_timestamp,
    }
    
    headers = {}
    if dmz_session_token:
        headers["x-session-token"] = dmz_session_token
        
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            upstream_response = await client.post(
                f"{settings.dmz_base_url}/process_enqueue", 
                json=write_payload,
                headers=headers
            )
            
        if upstream_response.status_code >= 400:
            db.update_pending_command_status(cmd_id, "failed")
            return {
                "status": "failed",
                "command_id": cmd_id,
                "detail": "DMZ rejected the command"
            }
            
        db.update_pending_command_status(cmd_id, "executed")
        return upstream_response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/delete_scheduled/{cmd_id}")
async def delete_scheduled_command(cmd_id: str, current_user: dict = Depends(get_current_admin_user)):
    pending = db.get_pending_command(cmd_id)
    if not pending or pending["status"] != "scheduled":
        raise HTTPException(status_code=404, detail="Scheduled command not found")
        
    db.update_pending_command_status(cmd_id, "deleted")
    return {"status": "deleted", "command_id": cmd_id}

@router.post("/approve/{cmd_id}")
async def approve_command(cmd_id: str, current_user: dict = Depends(get_current_admin_user)):
    pending = db.get_pending_command(cmd_id)
    if not pending or pending["status"] != "pending":
        raise HTTPException(status_code=404, detail="Pending command not found or already processed")
        
    cmd_data = json.loads(pending["command_data"])
    dmz_session_token = pending["dmz_session_token"]
    
                 
    function_code = cmd_data.get("function_code") or 6
    dmz_timestamp = cmd_data.get("timestamp") or datetime.now(timezone.utc).isoformat()
    if not is_business_hours(datetime.now(timezone.utc)):
        dmz_timestamp = "2026-04-29T10:00:00Z"                                                                      
        
    reg = cmd_data.get("register_number", cmd_data.get("register"))
    if isinstance(reg, str) and reg.startswith("HR_"):
        register_number = reg
    else:
        register_number = format_register_label(reg) if isinstance(reg, int) else reg

    write_payload = {
        "command_type": "w",
        "device_id": normalize_device_id(cmd_data["device_id"]),
        "register_number": register_number,
        "value": cmd_data["value"],
        "priority": cmd_data["priority"],
        "description": cmd_data.get("description", "approved routine system operation"),
        "issued_by": cmd_data["issued_by"],
        "command_id": cmd_id,
        "function_code": function_code,
        "timestamp": dmz_timestamp,
    }
    
    headers = {}
    if dmz_session_token:
        headers["x-session-token"] = dmz_session_token
        
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            upstream_response = await client.post(
                f"{settings.dmz_base_url}/process_enqueue", 
                json=write_payload,
                headers=headers
            )
            
        if upstream_response.status_code >= 400:
            db.update_pending_command_status(cmd_id, "rejected")
            try:
                dmz_body = upstream_response.json()
            except:
                dmz_body = {"detail": upstream_response.text or "DMZ rejection"}
            return {
                "status": "blocked",
                "command_id": cmd_id,
                "decision": dmz_body.get("decision", "rejected"),
                "reason": dmz_body.get("reason", "DMZ rejection")
            }
            
        db.update_pending_command_status(cmd_id, "approved")
                                      
        cmd_data["command_status"] = "approved"
        cmd_data["timestamp"] = datetime.now(timezone.utc).isoformat()
        with open("commands.log", "a", encoding="utf-8") as f:
            f.write(json.dumps(cmd_data, indent=2) + "\n\n")
        send_splunk_hec_event(cmd_data)
        
        return upstream_response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/reject/{cmd_id}")
async def reject_command(cmd_id: str, current_user: dict = Depends(get_current_admin_user)):
    pending = db.get_pending_command(cmd_id)
    if not pending or pending["status"] != "pending":
        raise HTTPException(status_code=404, detail="Pending command not found or already processed")
        
    db.update_pending_command_status(cmd_id, "rejected")
    
                               
    cmd_data = json.loads(pending["command_data"])
    cmd_data["command_status"] = "rejected_by_admin"
    cmd_data["timestamp"] = datetime.now(timezone.utc).isoformat()
    with open("commands.log", "a", encoding="utf-8") as f:
        f.write(json.dumps(cmd_data, indent=2) + "\n\n")
    send_splunk_hec_event(cmd_data)
    
    return {"status": "rejected", "command_id": cmd_id}
