# Command Dispatch Console

A full-stack application for the **IT Zone** to send commands to **OT Zone** devices through the **DMZ Zone**. This system provides a secure interface for dispatching Modbus commands to industrial control systems.

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Project Structure](#project-structure)
- [Project files & functions reference](#project-files--functions-reference)
- [Setup Instructions](#setup-instructions)
- [Usage](#usage)
- [API Documentation](#api-documentation)
- [Frontend Components](#frontend-components)
- [Backend Implementation](#backend-implementation)

## 🎯 Overview

The Command Dispatch Console is a three-zone security architecture system:

1. **IT Zone** - This frontend/backend application where operators send commands
2. **DMZ Zone** - Intermediate zone that receives commands from IT and forwards to OT
3. **OT Zone** - Operational Technology zone with PLCs and industrial devices

This application handles the **IT Zone** component, providing a web interface for command submission and an API for the DMZ to retrieve commands.

## 🏗️ Architecture

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│   IT Zone   │ ──────> │   DMZ Zone  │ ──────> │   OT Zone   │
│  (This App) │         │  (Gateway)  │         │   (PLCs)    │
└─────────────┘         └─────────────┘         └─────────────┘
```

### Flow:

1. Operator submits command via frontend (IT Zone)
2. Backend logs command and makes it available via API
3. DMZ Zone polls/retrieves commands from IT Zone API
4. DMZ Zone forwards commands to OT Zone devices
5. Commands execute on PLCs/devices

## ✨ Features

- **Role-Based Access Control**: Separate pages for Admin and User roles
- **Secure Authentication**: Multi-user password-hashed login system (SHA-256)
- **Admin Dashboard**: Read command interface with Splunk Analytics Dashboard button
- **User Interface**: Write command interface for regular users
- **Command Submission**: Send Modbus commands (Write/Read Holding Register)
- **Auto Function Code**: Automatically sets Modbus function codes based on command type
- **Device Selection**: Dropdown selection for devices (plc-001 to plc-009)
- **Register Selection**: Predefined register addresses (40001-40011)
- **Register Formatting**: Registers formatted as HR_40001 in logs and API
- **Device ID Normalization**: Device IDs normalized to uppercase (PLC-001)
- **Value Validation**: Range validation (0-65535) for write commands
- **Read Value Lookup**: Read commands find matching write values from command history
- **Read Command Details**: Read commands display user and timestamp information
- **Description Limit**: Maximum 500 characters with live counter
- **Priority Levels**: Normal and Critical priority options
- **Sequential Command IDs**: Auto-incrementing IDs (CMD-001 to CMD-100)
- **Command Logging**: All commands logged to `commands.log` in JSON format
- **Upstream Forwarding**: Commands forwarded to upstream ngrok endpoint
- **Input Validation**: Comprehensive server-side validation with Pydantic
- **CORS Enabled**: Configurable CORS with environment variable support
- **No-Cache Frontend Server**: Dedicated Python server with cache-control headers
- **Splunk Integration**: Splunk dashboard button opens in new window for real-time monitoring (Admin only)

## 📁 Project Structure

```
FYP/
├── README.md
├── PROJECT_CONTEXT.md
├── frontend/
│   ├── index.html
│   ├── login.html
│   ├── user.html
│   ├── admin.html
│   ├── styles.css
│   ├── app.js
│   ├── auth.js
│   ├── server.py
│   ├── DATASET GENERATION.py
│   └── assets/             (e.g. Logo.png)
├── backend/
│   ├── main.py
│   ├── config.py
│   ├── db.py
│   ├── auth.py
│   ├── jwt_utils.py
│   ├── approval.py
│   ├── users.py
│   ├── attack.py
│   ├── attack_simulation.py
│   ├── reports.py
│   ├── limiter.py
│   ├── trigger_rejected.py
│   ├── test.py
│   ├── test_dmz_write.py
│   ├── requirements.txt
│   ├── .env.example
│   ├── AUTH_SETUP.md
│   ├── auth.json           (runtime user store; may be auto-created)
│   ├── app.db / users.db   (SQLite; filename from `sqlite_db_path` in config / `.env`)
│   ├── command_counter.txt (runtime)
│   ├── session_command_counter.txt (runtime)
│   └── commands.log        (runtime)
```

## Project files & functions reference

This section lists each source file in the repository and the main symbols (functions, classes, routes) it defines. Generated or binary artifacts (`commands.log`, `*.db`, counters) are described only briefly.

### Root

| File | Purpose |
|------|---------|
| `README.md` | Project documentation (this file). |
| `PROJECT_CONTEXT.md` | Supplementary project context for developers. |

### `frontend/`

| File | Purpose | Functions / symbols |
|------|---------|---------------------|
| `app.js` | Shared globals, theme, authenticated `fetch` wrapper. | `getTheme`, `setTheme`, `toggleTheme`, `apiFetch`, `showToast`, `logout`, `getDmzSessionToken`; theme init IIFE `initTheme`; `DOMContentLoaded` auth guard. |
| `auth.js` | Lightweight auth helpers (if used by pages that include it). | `checkAuth`, `logout`. |
| `login.html` | Operator login; calls IT `/api/v1/login`; stores JWT and DMZ session token. | Inline: `checkDmzStatus` (DMZ reachability via `DMZ_URL`), `parseJsonSafe` (inside submit handler), JWT decode + redirect to `admin.html` or `user.html`. |
| `user.html` | User dashboard: tabs, DMZ session command list, CSV download. | Inline: `checkDmzHealth`, `toggleSidebar`, `openUserTab`, `fetchCommands`, `renderCommandsTable`, `downloadCsv`; `formatTimestamp` const; event listeners for forms. |
| `admin.html` | Admin dashboard: live/history tables, pending scheduled commands, user CRUD, attack simulation, Splunk link. | Inline: `getAccessToken`, `getDmzToken`, `apiFetch`, `showToast`, `logout`, `openAdminTab`, `openCmdTab`, `fetchCommands`, `updateStats`, `renderCommandsTable`, `fetchPending`, `executeScheduledCmd`, `deleteScheduledCmd`, `fetchUsers`, `deleteUser`, `promptAttackSimulation`, `closeModal`, `executeAttack`, `downloadCsv`, `openSplunkDashboard`, `checkDmzHealth`, `toggleScheduleTime`, `toggleSidebar`; `formatTimestamp` const; optional `DMZ_URL` fallback when `app.js` not loaded. |
| `index.html` | Alternate combined UI (tabs for write/read). | Inline: `openTab`, `logout`; form handlers in script block. |
| `styles.css` | Global layout, theme variables, components, responsive rules. | CSS only (no functions). |
| `server.py` | Serves static frontend on port **5600** with no-cache headers. | Class `NoCacheHTTPRequestHandler` with `end_headers` override. |
| `DATASET GENERATION.py` | Script to warm registers and POST many commands for dataset load testing. | `login`, `random_description`, `generate_value`; top-level loop posting writes. |

### `backend/`

| File | Purpose | Functions / classes / routes |
|------|---------|------------------------------|
| `main.py` | FastAPI app, CORS, scheduled command worker, command submit/read to DMZ, Splunk HEC, legacy login, JWT login with DMZ token. | **Lifespan / scheduler:** `lifespan`, `scheduler_loop`, `check_and_execute_scheduled_commands`. **Models:** `Command`, `CommandRequest` (method `validate_command` Pydantic validator), `LoginRequest`. **Helpers:** `generate_command_id`, `get_next_command_id`, `increment_session_counter`, `format_register_label`, `normalize_device_id`, `send_splunk_hec_event`, `is_business_hours`. **Routes:** `POST /api/submit_command`, `POST /api/login`, `POST /api/v1/login`, `POST /api/send_test_command`, `GET /health`, `GET /`. **Globals:** `UPSTREAM_URL`, `app`, middleware. |
| `config.py` | Pydantic settings from environment / `.env`. | Class `Settings` (`dmz_base_url`, JWT, DB path, rate limit fields, etc.); instance `settings`. |
| `db.py` | SQLite access for users and pending commands. | `get_db_connection`, `init_db`, `get_user_from_db`, `create_user`, `update_user_role`, `update_user_password`, `delete_user`, `get_all_users`, `verify_and_update_login`, `create_pending_command`, `get_pending_commands`, `get_pending_command`, `update_pending_command_status`. |
| `auth.py` | Password hashing and JSON-backed user file (`auth.json`). | `hash_password`, `_desired_users`, `init_auth`, `verify_password`, `get_user_role`, `change_password`. |
| `jwt_utils.py` | JWT creation and FastAPI dependencies. | `create_access_token`, `get_current_user`, `get_current_admin_user`, `get_optional_current_user`. |
| `approval.py` | Approval workflow and pending queue (rate-limited write request). | Router prefix `/api/v1`. **Routes:** `POST /request_write`, `GET /pending`, `POST /execute_scheduled/{cmd_id}`, `POST /delete_scheduled/{cmd_id}`, `POST /approve/{cmd_id}`, `POST /reject/{cmd_id}`. **Handlers:** `request_write`, `list_pending_commands`, `execute_scheduled_command`, `delete_scheduled_command`, `approve_command`, `reject_command`. |
| `users.py` | Admin-only user CRUD backed by `db`. | Classes `UserCreate`, `UserUpdate`. Router prefix `/api/v1/users`. **Routes:** `GET /api/v1/users`, `POST /api/v1/users`, `PUT /api/v1/users/{username}`, `DELETE /api/v1/users/{username}`. **Handlers:** `get_users`, `create_user`, `update_user`, `delete_user`. |
| `attack.py` | Admin-only attack simulation API. | Class `AttackRequest`. Router prefix `/api/v1`. **Route:** `POST /run_attack_simulation`. **Handler:** `run_attack_simulation` (password check, DMZ token fallback, runs `run_attacks` in executor). |
| `attack_simulation.py` | Synchronous script of benign + malicious commands for DMZ/ML testing. | `run_attacks(jwt_token, dmz_token)` with nested helpers `send_command`, `send_dmz`, `fire_burst` (thread pool burst). |
| `reports.py` | Session-scoped CSV or JSON report. | Router prefix `/api/v1/session`. **Route:** `GET /report`. **Handler:** `get_session_report` (reads `commands.log` by `dmz_session_token`, optional DMZ fetch, CSV or JSON). |
| `limiter.py` | SlowAPI limiter instance for rate limiting. | `limiter` (`Limiter(key_func=get_remote_address)`). |
| `trigger_rejected.py` | One-off script: POSTs malformed payloads to local `/api/submit_command` to trigger DMZ blocks for Splunk demos. | Top-level loop only (no function definitions). |
| `test.py` | End-to-end debug script: IT login → DMZ session poll → submit command → poll again. | Script flow using `config.settings` or `dotenv` fallback. |
| `test_dmz_write.py` | Minimal POST to DMZ `process_enqueue` for connectivity tests. | Top-level `requests.post` script. |
| `requirements.txt` | Pinned / listed Python dependencies for the backend. | — |
| `.env.example` | Example environment variables (copy to `.env`). | — |
| `AUTH_SETUP.md` | Auth file format and setup notes. | Markdown only. |

### Runtime / generated files (not hand-edited source)

| Path | Role |
|------|------|
| `backend/auth.json` | User credentials store used by `auth.py`. |
| `backend/app.db` / `backend/users.db` | SQLite databases (paths depend on `Settings.sqlite_db_path`). |
| `backend/commands.log` | Append-only JSON command log. |
| `backend/command_counter.txt` | Persisted total command counter seed. |
| `backend/session_command_counter.txt` | Per-session counter file. |

### API surface summary (mounted on `main:app`)

| Prefix / path | Module |
|---------------|--------|
| `/api/submit_command`, `/api/login`, `/api/v1/login`, `/api/send_test_command`, `/health`, `/` | `main.py` |
| `/api/v1/...` (approval, pending, scheduled) | `approval.py` |
| `/api/v1/users/...` | `users.py` |
| `/api/v1/run_attack_simulation` | `attack.py` |
| `/api/v1/session/report` | `reports.py` |

## 🚀 Setup Instructions

### Prerequisites

- Python 3.13+ (or 3.8+)
- pip (Python package manager)
- Modern web browser
- Two terminal windows (one for backend, one for frontend)

### Backend Setup

1. Open a terminal and navigate to the backend directory:

   ```powershell
   cd backend
   ```

2. Install dependencies:

   ```powershell
   pip install -r requirements.txt
   ```

3. Run the FastAPI server with uvicorn:

   ```powershell
   py -m uvicorn main:app --reload
   ```

   The backend server will start at `http://localhost:8000`

### Frontend Setup

1. **Open a new terminal window** (keep the backend terminal running)

2. Navigate to the frontend directory:

   ```powershell
   cd frontend
   ```

3. Run the frontend server:

   ```powershell
   python server.py
   ```

   The frontend server will start at `http://localhost:5600` with no-cache headers enabled.

4. Open your web browser and navigate to:

   ```
   http://localhost:5600
   ```

5. Default login credentials:

   **Admin Account:**
   - Username: `Admin1`
   - Password: `admin123`
   - Access: Admin page (Read commands + Splunk dashboard)
   
   **User Accounts:**
   - Username: `User1`
   - Password: `user11`
   - Access: User page (Write commands only)
   - Username: `User2`
   - Password: `user22`
   - Access: User page (Write commands only)

   **Note**: The authentication file (`auth.json`) is created automatically on first run with both default accounts. Passwords are stored as SHA-256 hashes. Users are routed to their respective pages based on role after login.

### Quick Start Summary

**Terminal 1 (Backend):**
```powershell
cd backend
pip install -r requirements.txt
py -m uvicorn main:app --reload
```

**Terminal 2 (Frontend):**
```powershell
cd frontend
python server.py
```

Then open `http://localhost:5600` in your browser.

## 📖 Usage

### User Role (Read Commands)

1. **Login**: Enter credentials (User1/user11 or User2/user22)
2. **Access User Page**: Automatically redirected to read command page after login
3. **Submit Read Command**:
   - Select Device: Choose from dropdown (plc-001 to plc-009)
   - Select Register: Choose from 40001-40011
   - Set Priority: Normal or Critical (must match priority of previous write command)
   - Submit: Click "Check Read Command Status"
4. **View Result**: Read value, user, and timestamp appear in the "Read Value" field (if a matching write command exists)

### Admin Role (Read Commands + Splunk Dashboard)

1. **Login**: Enter credentials (Admin1/admin123)
2. **Access Admin Page**: Automatically redirected to admin page after login
3. **Open Splunk Dashboard**: Click the "Open Splunk Analytics Dashboard" button to open Splunk in a new window (configure Splunk URL in admin.html)
4. **Submit Read Command**:
   - Select Device: Choose from dropdown (plc-001 to plc-009)
   - Select Register: Choose from 40001-40011
   - Set Priority: Normal or Critical (must match priority of previous write command)
   - Submit: Click "Check Read Command Status"
5. **View Result**: Read value, user, and timestamp appear in the "Read Value" field (if a matching write command exists)

### Configuring Splunk Dashboard (Admin)

To configure your Splunk dashboard button on the admin page:

1. Open `frontend/admin.html`
2. Locate the `openSplunkDashboard()` function
3. Replace the URL in the `window.open()` call with your Splunk dashboard URL:
   ```javascript
   window.open('https://your-splunk-instance.com/en-US/app/search/your-dashboard-id', '_blank');
   ```
4. The button will open the Splunk dashboard in a new browser window/tab

### Command Processing

**Write Commands:**
- Command is validated with strict rules
- Sequential command ID assigned (CMD-001, CMD-002, ... CMD-100)
- Function code is auto-calculated (6 for write commands)
- Device ID is normalized to uppercase (PLC-001)
- Register is formatted as HR_40001
- Timestamp is automatically added
- Command is logged to `commands.log`
- Command is forwarded to upstream ngrok endpoint
- Response confirms successful submission

**Read Commands:**
- Command is validated with strict rules
- Sequential command ID assigned
- Function code is auto-calculated (3 for read commands)
- Device ID is normalized to uppercase
- Register is formatted as HR_40001
- System searches `commands.log` for matching write command
- Matching criteria: same device ID, register, and priority
- Returns the most recent matching write value along with user and timestamp
- Command is logged to `commands.log`
- Command is forwarded to upstream ngrok endpoint
- Response includes read value, issued_by, and timestamp for display

### Field Constraints

- **Command Type**: Must be "w" (write) or "r" (read)
- **Device ID**: Must be plc-001 to plc-009 (lowercase)
- **Register**: Must be between 40001 and 40011
- **Value**: Must be between 0 and 65535
- **Priority**: Must be "normal" or "critical"
- **Description**: Maximum 500 characters
- **Issued By**: Auto-filled with logged-in username ("Admin1" or "User", readonly)
- **Command ID**: Sequential from CMD-001 to CMD-100

## 🔌 API Documentation

### Base URL

```
http://localhost:8000
```

### Endpoints

#### 1. Login

**POST** `/api/login`

Authenticate user and get session.

**Request Body:**

```json
{
  "username": "Admin1",
  "password": "admin123"
}
```

**Response (Admin):**

```json
{
  "status": "success",
  "message": "Login successful",
  "username": "Admin1",
  "role": "admin"
}
```

**Response (User):**

```json
{
  "status": "success",
  "message": "Login successful",
  "username": "User",
  "role": "user"
}
```

#### 2. Submit Command

**POST** `/api/submit_command`

Submit a new command to the system. Supports both write and read commands.

**Write Command Request Body:**

```json
{
  "command_type": "w",
  "device_id": "plc-001",
  "register": 40001,
  "value": 100,
  "priority": "normal",
  "description": "Set pump speed",
  "issued_by": "User"
}
```

**Read Command Request Body:**

```json
{
  "command_type": "r",
  "device_id": "plc-001",
  "register": 40001,
  "value": null,
  "priority": "normal",
  "description": "",
  "issued_by": "Admin1"
}
```

**Field Validations:**
- `command_type`: Must be "w" (write) or "r" (read)
- `device_id`: Must be "plc-001" to "plc-009" (case-insensitive, normalized to uppercase)
- `register`: Must be between 40001 and 40011
- `value`: 
  - Required for write commands, must be between 0 and 65535
  - Must be `null` or omitted for read commands
- `priority`: Must be "normal" or "critical"
- `description`: Maximum 500 characters (optional)
- `issued_by`: Must be "Admin1" or "User"

**Write Command Response:**

```json
{
  "status": "success",
  "command_id": "CMD-001"
}
```

**Read Command Response:**

```json
{
  "status": "success",
  "command_id": "CMD-002",
  "read_value": 100,
  "issued_by": "Admin1",
  "timestamp": "2025-11-14T15:52:10.123456+00:00"
}
```

If no matching write command is found:

```json
{
  "status": "success",
  "command_id": "CMD-002",
  "read_value": null,
  "issued_by": "Admin1",
  "timestamp": "2025-11-14T15:52:10.123456+00:00"
}
```

**Note**: 
- Command IDs are sequential (CMD-001, CMD-002, ... CMD-100). After 100 commands, an error will be returned.
- Read commands search for matching write commands based on device ID, register, and priority.
- Commands are forwarded to upstream ngrok endpoint: `https://entrap-underfed-collapse.ngrok-free.dev/process_enqueue`

#### 3. Get All Commands

**GET** `/api/commands`

Retrieve all commands with optional filtering.

**Query Parameters:**

- `limit` (optional): Limit number of results
- `command_id` (optional): Filter by command ID
- `device_id` (optional): Filter by device ID
- `priority` (optional): Filter by priority (normal/critical)

**Example:**

```
GET /api/commands?limit=10&device_id=plc-001&priority=critical
```

**Response:**

```json
{
  "status": "success",
  "count": 5,
  "commands": [
    {
      "command_type": "w",
      "device_id": "plc-001",
      "register": 40001,
      "value": 100,
      "priority": "normal",
      "description": "Set pump speed",
      "issued_by": "Admin1",
      "function_code": 6,
      "command_id": "CMD-001",
      "timestamp": "2025-11-14T15:51:55.692729+00:00"
    }
  ]
}
```

#### 4. Get Command by ID

**GET** `/api/commands/{command_id}`

Retrieve a specific command by its ID.

**Example:**

```
GET /api/commands/CMD-001
```

**Response:**

```json
{
  "status": "success",
  "command": {
    "command_type": "w",
    "device_id": "plc-001",
    "register": 40001,
    "value": 100,
    "priority": "normal",
    "description": "Set pump speed",
    "issued_by": "Admin1",
    "function_code": 6,
    "command_id": "CMD-001",
    "timestamp": "2025-11-14T15:51:55.692729+00:00"
  }
}
```

## 🎨 Frontend Components

### Login Page (`login.html`)

- Dark-themed authentication form with glassmorphism design
- Session-based authentication using `sessionStorage`
- Role-based routing after successful login
- Error message display for failed login attempts
- Automatic redirect to user.html (User role) or admin.html (Admin role)

### User Page (`user.html`)

- **Read Command Interface** for regular users
- **Form Fields**:
  - Device ID: Dropdown with devices (plc-001 to plc-009)
  - Register: Dropdown (40001-40011)
  - Priority: Normal/Critical dropdown
  - Read Value Display: Shows the retrieved value, user, and timestamp from matching write command
  - Issued By: Auto-filled with logged-in username (readonly)
- **Status Messages**: Success/error messages displayed after command submission
- Dark theme with modern UI design

### Admin Page (`admin.html`)

- **Read Command Interface** for administrators
- **Splunk Dashboard Integration**:
  - Button to open Splunk Analytics Dashboard in new window
  - Configure Splunk URL in JavaScript function
- **Read Command Form**:
  - Device ID: Dropdown with devices (plc-001 to plc-009)
  - Register: Dropdown (40001-40011)
  - Priority: Normal/Critical dropdown
  - Read Value Display: Shows the retrieved value, user, and timestamp from matching write command
  - Issued By: Auto-filled with logged-in username (readonly)
- **Write Command Form** (Admin can also write):
  - Same fields as User page
  - Description field with proper spacing and sizing
- **Status Messages**: Success/error messages displayed after command submission
- Dark theme with modern UI design

### Frontend Server (`server.py`)

- Python HTTP server running on port 5600
- No-cache headers enabled (Cache-Control, Pragma, Expires)
- Serves static files from frontend directory
- Prevents browser caching for development

### Styling (`styles.css`)

- Dark theme with gradient backgrounds
- Glassmorphism effects with backdrop blur
- Modern, responsive layout
- Clean form styling
- Animated background elements
- Status message display (success/error)
- Mobile-responsive design

## ⚙️ Backend Implementation

### Command Model

The `Command` Pydantic model includes:

- `command_type`: Type of command ("w" or "r")
- `device_id`: Target device identifier (plc-001 to plc-009)
- `register_number`: Modbus register address (40001-40011)
- `value`: Command value (0-65535)
- `priority`: Normal or Critical
- `description`: Optional description (max 500 characters)
- `issued_by`: Username of the logged-in user ("Admin1" or "User")
- `function_code`: Auto-calculated Modbus function code
- `command_id`: Sequential identifier (CMD-001 to CMD-100)
- `timestamp`: UTC timestamp (auto-generated)

### Function Code Mapping

- **"w" (Write)** → Function Code `6`
- **"r" (Read)** → Function Code `3`

### Input Validation

All fields are validated server-side with Pydantic validators:

- **Command Type**: Must be "w" or "r"
- **Device ID**: Must match pattern `plc-001` to `plc-009` (lowercase)
- **Register**: Must be between 40001 and 40011
- **Value**: Must be between 0 and 65535
- **Priority**: Must be "normal" or "critical"
- **Description**: Maximum 500 characters
- **Issued By**: Must be "Admin1" or "User"

### Sequential Command IDs

Command IDs are generated sequentially:
- First command: `CMD-001`
- Second command: `CMD-002`
- ... up to `CMD-100`
- Counter is stored in `command_counter.txt`
- After 100 commands, an error is returned

### Command Logging

All commands are logged to `backend/commands.log` in JSON format with:

- Full command details
- Timestamp
- Sequential command ID (CMD-001, CMD-002, etc.)
- Auto-calculated function code

### Authentication System

- **Password Hashing**: SHA-256 hashing for secure password storage
- **Multi-User Support**: Multiple users stored in `backend/auth.json`
- **Storage Format**: JSON array with user objects containing username, password_hash, and role
- **Default Credentials**: 
  - **Admin Account**:
    - Username: `Admin1`
    - Password: `admin123`
    - Role: `admin`
  - **User Account**:
    - Username: `User`
    - Password: `user123`
    - Role: `user`
- **Auto-Initialization**: `auth.json` is created automatically on first run with both accounts
- **Migration**: Old single-user format automatically migrates to multi-user format
- **Login Endpoint**: `/api/login` returns username and role for frontend routing

### CORS Configuration

CORS middleware is configured to allow:

- All origins (`*`)
- All methods
- All headers
- Credentials

**Note**: For production, restrict origins to specific domains.

### Upstream URL Configuration

Commands are forwarded to an upstream endpoint:

- **Default Upstream URL**: `https://entrap-underfed-collapse.ngrok-free.dev/process_enqueue`
- Configured in `backend/main.py` as `UPSTREAM_URL`
- All write and read commands are forwarded to this endpoint
- Uses `httpx` for async HTTP requests with 10-second timeout

### CORS Configuration

CORS is configured with environment variable support:

- **Environment Variable**: `ALLOWED_ORIGINS` (comma-separated list)
- **Default Origins** (development):
  - `http://localhost:5600`
  - `http://127.0.0.1:5600`
  - `https://entrap-underfed-collapse.ngrok-free.dev`
- For production, set `ALLOWED_ORIGINS` environment variable

## 🔒 Security Notes

- **Authentication**: Currently uses simple session-based auth. For production, implement proper authentication (JWT, OAuth, etc.)
- **CORS**: Currently allows all origins. Restrict in production.
- **Input Validation**: Pydantic models provide automatic validation
- **Error Handling**: All endpoints include try-catch error handling

## 📝 Command Log Format

Commands are logged in JSON format to `backend/commands.log`:

**Write Command Example:**
```json
{
  "command_type": "w",
  "device_id": "PLC-001",
  "register": 40001,
  "register_number": "HR_40001",
  "value": 100,
  "priority": "normal",
  "description": "Set pump speed",
  "issued_by": "User",
  "function_code": 6,
  "command_id": "CMD-001",
  "timestamp": "2025-11-14T15:51:55.692729+00:00"
}
```

**Read Command Example:**
```json
{
  "command_type": "r",
  "device_id": "PLC-001",
  "register": 40001,
  "register_number": "HR_40001",
  "value": null,
  "priority": "normal",
  "description": "",
  "issued_by": "Admin1",
  "function_code": 3,
  "command_id": "CMD-002",
  "timestamp": "2025-11-14T15:52:10.123456+00:00"
}
```

**Note**: 
- Device IDs are stored in uppercase (PLC-001)
- Registers are stored with both numeric (40001) and formatted (HR_40001) versions
- Commands are separated by double newlines in the log file
- `issued_by` field reflects the actual username of the logged-in user

## 🔐 Authentication

### Default Credentials

**Admin Account:**
- **Username**: `Admin1`
- **Password**: `admin123`
- **Role**: `admin`
- **Access**: Admin page with read commands and Splunk dashboard

**User Account:**
- **Username**: `User`
- **Password**: `user123`
- **Role**: `user`
- **Access**: User page with write commands only

### User Structure

Users are stored in `backend/auth.json` with the following format:

```json
{
  "users": [
    {
      "username": "Admin1",
      "password_hash": "<sha256_hash>",
      "role": "admin"
    },
    {
      "username": "User",
      "password_hash": "<sha256_hash>",
      "role": "user"
    }
  ]
}
```

### Password Management

Passwords are stored as SHA-256 hashes. To change a password:

1. Generate a hash for your new password:
   ```python
   import hashlib
   password = "your_new_password"
   hash = hashlib.sha256(password.encode()).hexdigest()
   print(hash)
   ```

2. Update `backend/auth.json` with the new hash for the specific user

3. To add new users, add a new object to the `users` array with username, password_hash, and role

See `backend/AUTH_SETUP.md` for more details.

## 🛠️ Dependencies

### Backend

- Declared in `backend/requirements.txt`: FastAPI, Uvicorn, httpx, Pydantic, requests.
- The code also imports **pydantic-settings**, **python-jose** (`jwt`), **bcrypt**, **slowapi**, and **python-multipart** (typical FastAPI form/JSON). Install anything missing if the server fails to start.

See `backend/requirements.txt` for pinned lines where present.

### Frontend

- Python 3.x (built-in `http.server` and `socketserver` modules)
- No external dependencies required

## 🔄 Workflow

### Read Command Workflow (User Role)

1. **User Login**: Authenticate via login page (User/user123)
2. **Access User Page**: Automatically redirected to user.html after login
3. **Fill Read Form**: Enter command details (device, register, priority)
4. **Submit**: Frontend sends POST to `/api/submit_command` with `command_type: "r"` and `issued_by: "User"`
4. **Backend Processing**:
   - Validates all input fields
   - Auto-calculates function code (3 for read)
   - Normalizes device ID to uppercase
   - Formats register as HR_40001
   - Generates sequential command ID
   - Adds UTC timestamp
   - Searches `commands.log` for matching write command
   - Matching: same device ID, register, and priority
   - Returns most recent matching write value
   - Logs read command to `commands.log`
   - Forwards command to upstream ngrok endpoint
5. **Response**: Read value, user, and timestamp displayed in "Read Value" field (or error if no match found)

### Read Command Workflow (Admin Role)

1. **Admin Login**: Authenticate via login page (Admin1/admin123)
2. **Access Admin Page**: Automatically redirected to admin.html after login
3. **View Splunk Dashboard**: Real-time analytics displayed (if configured)
4. **Fill Read Form**: Enter command details (device, register, priority)
5. **Submit**: Frontend sends POST to `/api/submit_command` with `command_type: "r"` and `issued_by: "Admin1"`
4. **Backend Processing**:
   - Validates all input fields
   - Auto-calculates function code (3 for read)
   - Normalizes device ID to uppercase
   - Formats register as HR_40001
   - Generates sequential command ID
   - Adds UTC timestamp
   - Searches `commands.log` for matching write command
   - Matching: same device ID, register, and priority
   - Returns most recent matching write value
   - Logs read command to `commands.log`
   - Forwards command to upstream ngrok endpoint
5. **Response**: Read value displayed in "Read Value" field (or error if no match found)

## 🐛 Troubleshooting

### Backend won't start

- Check Python version: `py --version` (should be 3.8+)
- Install dependencies: `pip install -r requirements.txt`
- Check if port 8000 is available
- Ensure you're in the `backend` directory when running commands

### Frontend server won't start

- Check if port 5600 is already in use
- Ensure you're in the `frontend` directory when running `python server.py`
- Check Python version: `python --version`

### Frontend can't connect to backend

- Ensure backend is running on `http://localhost:8000` (check Terminal 1)
- Ensure frontend server is running on `http://localhost:5600` (check Terminal 2)
- Check CORS settings in `backend/main.py`
- Verify browser console for errors (F12)
- Make sure both servers are running in separate terminals

### Commands not appearing

- Check `backend/commands.log` file exists
- Verify file permissions
- Check backend terminal for error messages
- Verify upstream ngrok endpoint is accessible

### Read commands return no value

- Ensure a matching write command exists in `commands.log`
- Matching criteria: same device ID (case-insensitive), same register, same priority
- Check that the write command was successfully logged before the read command

### Splunk dashboard button not working

- Verify the Splunk URL is correctly configured in `frontend/admin.html` in the `openSplunkDashboard()` function
- Check browser popup blocker settings (may block new window)
- Ensure the Splunk instance is accessible from your network
- Verify the URL is correct and the Splunk dashboard loads when accessed directly

## 📚 Additional Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Pydantic Documentation](https://docs.pydantic.dev/)
- [Modbus Protocol](https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf)

## 👤 Author

FYP Project - IT Zone Command Dispatch Console

## 📄 License

This project is part of a Final Year Project (FYP).

---

**Note**: This is a development version. Production deployment should include:

- Proper authentication/authorization
- Database instead of file logging
- HTTPS/TLS encryption
- Rate limiting
- Input sanitization
- Error logging and monitoring
