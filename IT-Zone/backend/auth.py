import hashlib
import json
import os

AUTH_FILE = "auth.json"

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def _desired_users() -> dict:
    """Return the desired default user set with hashed passwords."""
    return {
        "users": [
            {
                "username": "Admin1",
                "password_hash": hash_password("admin123"),
                "role": "admin",
            },
            {
                "username": "User1",
                "password_hash": hash_password("user11"),
                "role": "user",
            },
            {
                "username": "User2",
                "password_hash": hash_password("user22"),
                "role": "user",
            },
        ]
    }

def init_auth():
    desired = _desired_users()

    if not os.path.exists(AUTH_FILE):
        with open(AUTH_FILE, "w", encoding="utf-8") as f:
            json.dump(desired, f, indent=2)
        return desired

    with open(AUTH_FILE, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            data = {}

                                                                      
    if not isinstance(data, dict) or "users" not in data:
        with open(AUTH_FILE, "w", encoding="utf-8") as f:
            json.dump(desired, f, indent=2)
        return desired

    existing_usernames = {user.get("username") for user in data.get("users", []) if isinstance(user, dict)}
    desired_usernames = {user["username"] for user in desired["users"]}

                                                                                                 
    if existing_usernames != desired_usernames:
        with open(AUTH_FILE, "w", encoding="utf-8") as f:
            json.dump(desired, f, indent=2)
        return desired

                                                                 
    updated = False
    desired_hash_lookup = {u["username"]: u["password_hash"] for u in desired["users"]}
    for user in data["users"]:
        username = user.get("username")
        desired_hash = desired_hash_lookup.get(username)
        if desired_hash and user.get("password_hash") != desired_hash:
            user["password_hash"] = desired_hash
            updated = True

    if updated:
        with open(AUTH_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    return data

def verify_password(username: str, password: str):
    from db import verify_and_update_login, get_db_connection
    from datetime import datetime, timezone
    
    is_valid, role = verify_and_update_login(username, password)
    if is_valid:
        return True, role
        
                                
    users_data = init_auth()
    password_hash = hash_password(password)
    for user in users_data["users"]:
        if user["username"] == username and user["password_hash"] == password_hash:
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET last_login = ? WHERE username = ?', 
                               (datetime.now(timezone.utc).isoformat(), username))
                conn.commit()
                conn.close()
            except Exception:
                pass
            return True, user.get("role", "user")
    return False, ""

def get_user_role(username: str) -> str:
    from db import get_user_from_db
    user_db = get_user_from_db(username)
    if user_db:
        return user_db["role"]
        
              
    users_data = init_auth()
    for user in users_data["users"]:
        if user["username"] == username:
            return user.get("role", "user")
    return ""

def change_password(username: str, old_password: str, new_password: str) -> bool:
    users_data = init_auth()
    for user in users_data["users"]:
        if user["username"] == username:
            if user["password_hash"] == hash_password(old_password):
                user["password_hash"] = hash_password(new_password)
                with open(AUTH_FILE, "w", encoding="utf-8") as f:
                    json.dump(users_data, f, indent=2)
                return True
            return False
    return False

