# Authentication Setup

## Default Credentials

When the application runs for the first time, it creates an authentication file with default credentials:

- **Username**: `Admin1`
- **Password**: `admin123`

## How It Works

1. Authentication data is stored in `backend/auth.json`
2. Passwords are hashed using SHA-256
3. The file is created automatically on first run
4. Only one admin account exists: `Admin1`

## Security

- Passwords are hashed, not stored in plain text
- Authentication file is stored locally in the backend directory
- Login is verified via `/api/login` endpoint

## Changing Password

To change the password, you can:
1. Edit `backend/auth.json` directly (you'll need to hash the new password)
2. Or use the `change_password()` function in `auth.py` programmatically

## Password Hashing

The system uses SHA-256 hashing. To generate a hash for a new password:

```python
import hashlib
password = "your_password"
hash = hashlib.sha256(password.encode()).hexdigest()
print(hash)
```

Then update `auth.json`:
```json
{
  "username": "Admin1",
  "password_hash": "<generated_hash>"
}
```

