import requests
payload = {
    "command_type": "w",
    "device_id": "PLC-001",
    "register_number": "HR_40001",
    "value": 123,
    "priority": "normal",
    "description": "ml log test",
    "issued_by": "Admin1",
    "function_code": 6,
    "command_id": "CMD-DEADBEEF1234",                            
    "timestamp": "2026-04-29T10:00:00Z"
}
r = requests.post("https://entrap-underfed-collapse.ngrok-free.dev/process_enqueue", json=payload)
print(r.status_code, r.text)