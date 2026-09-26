import sqlite3
import json
from datetime import datetime, timezone
import bcrypt
from config import settings

def get_db_connection():
    conn = sqlite3.connect(settings.sqlite_db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
                        
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            hashed_password TEXT,
            role TEXT,
            last_login TEXT
        )
    ''')
    
                                   
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS pending_commands (
            id TEXT PRIMARY KEY,
            command_data TEXT,
            dmz_session_token TEXT,
            status TEXT,
            created_at TEXT,
            issued_by TEXT,
            scheduled_at TEXT
        )
    ''')
    
                                                            
    try:
        cursor.execute('ALTER TABLE pending_commands ADD COLUMN scheduled_at TEXT')
        conn.commit()
    except sqlite3.OperationalError:
        pass                        
    
                                            
    default_users = [
        ("Admin1", "password1", "admin"),
        ("User1", "password1", "user"),
        ("User2", "password2", "user")
    ]
    
    for username, pwd, role in default_users:
        cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
        if not cursor.fetchone():
            hashed_pwd = bcrypt.hashpw(pwd.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cursor.execute('''
                INSERT INTO users (username, hashed_password, role)
                VALUES (?, ?, ?)
            ''', (username, hashed_pwd, role))
            
    conn.commit()
    conn.close()

def get_user_from_db(username: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def create_user(username: str, password: str, role: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        hashed_pwd = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute('''
            INSERT INTO users (username, hashed_password, role)
            VALUES (?, ?, ?)
        ''', (username, hashed_pwd, role))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def update_user_role(username: str, role: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET role = ? WHERE username = ?', (role, username))
    conn.commit()
    updated = cursor.rowcount > 0
    conn.close()
    return updated

def update_user_password(username: str, password: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    hashed_pwd = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    cursor.execute('UPDATE users SET hashed_password = ? WHERE username = ?', (hashed_pwd, username))
    conn.commit()
    updated = cursor.rowcount > 0
    conn.close()
    return updated

def delete_user(username: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE username = ?', (username,))
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    return deleted

def get_all_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT username, role, last_login FROM users')
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def verify_and_update_login(username: str, password: str):
    user = get_user_from_db(username)
    if user:
        try:
            is_valid = bcrypt.checkpw(password.encode('utf-8'), user["hashed_password"].encode('utf-8'))
        except Exception:
            is_valid = False
            
        if is_valid:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET last_login = ? WHERE username = ?', 
                           (datetime.now(timezone.utc).isoformat(), username))
            conn.commit()
            conn.close()
            return True, user["role"]
    return False, ""

def create_pending_command(cmd_id: str, command_data: dict, dmz_session_token: str, issued_by: str, status: str = "pending", scheduled_at: str = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO pending_commands (id, command_data, dmz_session_token, status, created_at, issued_by, scheduled_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (cmd_id, json.dumps(command_data), dmz_session_token, status, datetime.now(timezone.utc).isoformat(), issued_by, scheduled_at))
    conn.commit()
    conn.close()

def get_pending_commands(status: str = "pending"):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM pending_commands WHERE status = ?', (status,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_pending_command(cmd_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM pending_commands WHERE id = ?', (cmd_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def update_pending_command_status(cmd_id: str, status: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE pending_commands SET status = ? WHERE id = ?', (status, cmd_id))
    conn.commit()
    conn.close()
