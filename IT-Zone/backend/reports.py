from fastapi import APIRouter, Depends, HTTPException, Header
from fastapi.responses import Response
import httpx
import csv
import io
import os
import json
from typing import Optional
from jwt_utils import get_current_user
from config import settings

router = APIRouter(prefix="/api/v1/session", tags=["Reports"])

@router.get("/report")
async def get_session_report(
    format: str = "csv",
    x_dmz_session_token: Optional[str] = Header(None, alias="X-DMZ-Session-Token")
):
    commands = []
                                                   
    if os.path.exists("commands.log"):
        try:
            with open("commands.log", "r", encoding="utf-8") as f:
                content = f.read()
                chunks = content.split("\n\n")
                for chunk in chunks:
                    if chunk.strip():
                        try:
                            cmd_data = json.loads(chunk)
                            if cmd_data.get("dmz_session_token") == x_dmz_session_token:
                                commands.append(cmd_data)
                        except:
                            pass
        except Exception as e:
            print(f"Error reading commands.log: {e}")
            
                                                      
    if not commands and x_dmz_session_token:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"{settings.dmz_base_url}/api/session/commands",
                    headers={
                        "x-session-token": x_dmz_session_token,
                        "ngrok-skip-browser-warning": "true"
                    }
                )
                if resp.ok:
                    data = resp.json()
                    commands = data if isinstance(data, list) else data.get("commands", [])
        except Exception as e:
            print(f"Failed to fetch from DMZ: {e}")
        
    if format.lower() == "csv":
        output = io.StringIO()
        if not commands:
            writer = csv.writer(output)
            writer.writerow(["No commands found for this session"])
        else:
                                                    
            headers = set()
            for cmd in commands:
                headers.update(cmd.keys())
            headers = sorted(list(headers))
            
            writer = csv.DictWriter(output, fieldnames=headers)
            writer.writeheader()
            for cmd in commands:
                writer.writerow(cmd)
                
        csv_content = output.getvalue()
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=session_report.csv"}
        )
        
    return {"commands": commands}
