# ICS Command Dispatch Console — Project Context

This document gives **architecture and code-level context** for developers and for LLMs assisting on the repo. End-user setup, credentials, and long-form API prose live in **`README.md`**; use this file for **how the system is wired** and **where logic lives**.

---

## 1. High-level overview

The Command Dispatch Console is the **IT zone** of a three-part flow:

| Zone | Role |
|------|------|
| **IT (this repo)** | FastAPI backend + static HTML/JS frontend: login, RBAC, approval / scheduling, command submission, Splunk HEC logging, CSV session reports. |
| **DMZ (external service)** | Receives commands at `{DMZ_BASE_URL}/process_enqueue`, runs validation / ML / session APIs (e.g. `/api/login`, `/api/session/commands`). Base URL comes from `backend/config.py` / `.env`. |
| **OT** | PLCs and field devices; not implemented in this repository. |

**Frontend:** vanilla HTML/CSS/JS (no React/Vue). Shared helpers in `frontend/app.js`; role-specific pages `login.html`, `user.html`, `admin.html`; optional legacy-style `index.html`.

**Backend:** FastAPI app in `backend/main.py` with routers from `approval.py`, `users.py`, `attack.py`, `reports.py`.

---

## 2. Repository layout

```
FYP/
├── README.md
├── PROJECT_CONTEXT.md          ← this file
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
│   └── assets/                 (e.g. Logo.png)
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
│   ├── auth.json               (runtime; SHA-256 hashes, see auth.py)
│   ├── *.db                    (SQLite; filename = `sqlite_db_path` in config)
│   ├── command_counter.txt
│   ├── session_command_counter.txt
│   └── commands.log
```

---

## 3. Frontend (`frontend/`) — files and functions

Global API base URLs and **`DMZ_URL`** are set in `app.js` (and optionally duplicated as a fallback in `admin.html` if `DMZ_URL` were undefined).

| File | Responsibility | Main symbols |
|------|------------------|--------------|
| **`app.js`** | Theme (`data-theme`), JWT + DMZ headers on fetch, toast helper, logout. | `getTheme`, `setTheme`, `toggleTheme`, `apiFetch`, `showToast`, `logout`, `getDmzSessionToken`, IIFE `initTheme`, `DOMContentLoaded` guard. |
| **`auth.js`** | Optional small helpers for pages that include it. | `checkAuth`, `logout`. |
| **`login.html`** | POST `http://localhost:8000/api/v1/login`; stores `jwt`, `dmz_session_token`, `username`, `role`; redirects to `admin.html` or `user.html`. | `checkDmzStatus` (fetch base `DMZ_URL` with `ngrok-skip-browser-warning`), inline `parseJsonSafe`, JWT payload decode. |
| **`user.html`** | User UI: live/history tables from **DMZ** `GET /api/session/commands`; **read** form posts to IT **`/api/submit_command`**; CSV via IT **`/api/v1/session/report`**. | `checkDmzHealth`, `toggleSidebar`, `openUserTab`, `fetchCommands`, `renderCommandsTable`, `downloadCsv`, `formatTimestamp`. |
| **`admin.html`** | Admin UI: dashboard, history, direct read/write to IT **`/api/submit_command`** (the code path for “request approval” exists but **`requestApproval` is currently hardcoded `false`**), **pending scheduled** commands, user CRUD, attack simulation modal, Splunk button, DMZ health pill. | `getAccessToken`, `getDmzToken`, `apiFetch`, `showToast`, `logout`, `openAdminTab`, `openCmdTab`, `fetchCommands`, `updateStats`, `renderCommandsTable`, `fetchPending`, `executeScheduledCmd`, `deleteScheduledCmd`, `fetchUsers`, `deleteUser`, `promptAttackSimulation`, `closeModal`, `executeAttack`, `downloadCsv`, `openSplunkDashboard`, `checkDmzHealth`, `toggleScheduleTime`, `toggleSidebar`, `formatTimestamp`. |
| **`index.html`** | Alternate single-page layout with write/read tabs. | `openTab`, `logout`; inline form handlers. |
| **`styles.css`** | Layout, theme variables, tables, modals, toasts. | CSS only. |
| **`server.py`** | Static file server on **port 5600** with no-cache headers. | Class `NoCacheHTTPRequestHandler.end_headers`. |
| **`DATASET GENERATION.py`** | Load-testing script: login sessions, warm registers, POST many writes. | `login`, `random_description`, `generate_value`. |

**Live dashboard:** `user.html` / `admin.html` poll **`GET {DMZ_URL}/api/session/commands`** with header **`x-session-token`** (and often `ngrok-skip-browser-warning`), not the IT backend, so the DMZ owns session-scoped command history for the UI.

---

## 4. Backend (`backend/`) — modules, routes, and functions

### 4.1 `main.py` — application core

| Category | Symbols |
|----------|---------|
| **App lifecycle** | `lifespan`, `scheduler_loop`, `check_and_execute_scheduled_commands` (SQLite `pending_commands` with `status='scheduled'`, POST to DMZ `UPSTREAM_URL`). |
| **Models** | `Command`, `CommandRequest` (field alias `register` → `register_number`; validator **`validate_command`** unless `allow_malformed`), `LoginRequest`. |
| **Helpers** | `generate_command_id`, `get_next_command_id`, `increment_session_counter`, `format_register_label`, `normalize_device_id`, `send_splunk_hec_event`, `is_business_hours`. |
| **Routes** | `POST /api/submit_command`, `POST /api/login`, `POST /api/v1/login`, `POST /api/send_test_command`, `GET /health`, `GET /`. |
| **Globals** | `UPSTREAM_URL = f"{settings.dmz_base_url}/process_enqueue"`, CORS `allowed_origins`, Splunk HEC constants. |

**`POST /api/v1/login`:** validates user, creates JWT, calls **`POST {dmz_base_url}/api/login`** to obtain **`dmz_session_token`** for the browser.

**`POST /api/submit_command`:** RBAC (writes admin-only in normal mode), builds DMZ payload, optional **`X-DMZ-Session-Token`** → **`x-session-token`** upstream, read/write branches via `httpx`.

### 4.2 `config.py`

| Symbol | Role |
|--------|------|
| `Settings` | `pydantic_settings.BaseSettings`: `dmz_base_url`, JWT fields, `sqlite_db_path`, `rate_limit_max`, `rate_limit_window`, etc.; reads `.env`. |
| `settings` | Singleton used across the app. |

### 4.3 `db.py` — SQLite

| Function | Role |
|----------|------|
| `get_db_connection` | Opens SQLite using `settings.sqlite_db_path`. |
| `init_db` | Creates `users` and `pending_commands` tables if missing. |
| `get_user_from_db`, `create_user`, `update_user_role`, `update_user_password`, `delete_user`, `get_all_users` | User CRUD. |
| `verify_and_update_login` | **bcrypt** password check + `last_login` update. |
| `create_pending_command`, `get_pending_commands`, `get_pending_command`, `update_pending_command_status` | Pending / scheduled command rows. |

### 4.4 `auth.py` — dual credential source

| Function | Role |
|----------|------|
| `hash_password` | **SHA-256** hex digest for `auth.json` users. |
| `_desired_users`, `init_auth` | Ensures `auth.json` exists with default user list. |
| `verify_password` | **First:** `db.verify_and_update_login` (**bcrypt** in SQLite). **Fallback:** `auth.json` SHA-256 match + optional `last_login` touch in DB. |
| `get_user_role`, `change_password` | Role lookup and password change helper. |

### 4.5 `jwt_utils.py`

| Function | Role |
|----------|------|
| `create_access_token` | JWT with expiry from `settings`. |
| `get_current_user` | FastAPI dependency: Bearer JWT → user dict. |
| `get_current_admin_user` | Requires `role == "admin"`. |
| `get_optional_current_user` | Parses `Authorization` without forcing auth (used by `submit_command`). |

Uses **`python-jose`** (`from jose import jwt`), not the PyPI package name `PyJWT`.

### 4.6 `approval.py` — prefix `/api/v1`

| Route | Handler | Notes |
|-------|---------|--------|
| `POST /request_write` | `request_write` | **`@limiter.limit(...)`** — rate limit from `settings`. |
| `GET /pending` | `list_pending_commands` | Query `status` (e.g. `pending`, `scheduled`). |
| `POST /execute_scheduled/{cmd_id}` | `execute_scheduled_command` | Sends stored command to DMZ. |
| `POST /delete_scheduled/{cmd_id}` | `delete_scheduled_command` | Removes scheduled row. |
| `POST /approve/{cmd_id}` | `approve_command` | Approves pending write. |
| `POST /reject/{cmd_id}` | `reject_command` | Rejects pending write. |

Imports helpers from **`main`** (`CommandRequest`, IDs, Splunk, etc.); keep import graph in mind when refactoring.

### 4.7 `users.py` — prefix `/api/v1/users`

| Route | Handler |
|-------|---------|
| `GET ""` | `get_users` |
| `POST ""` | `create_user` |
| `PUT /{username}` | `update_user` |
| `DELETE /{username}` | `delete_user` |

Models: `UserCreate`, `UserUpdate`. All routes require **admin** via `get_current_admin_user`.

### 4.8 `attack.py` + `attack_simulation.py`

| File | Role |
|------|------|
| **`attack.py`** | `POST /api/v1/run_attack_simulation`: verifies admin password via `verify_and_update_login`, resolves DMZ token (header or DMZ login fallback), runs **`run_attacks`** in a thread pool executor. |
| **`attack_simulation.py`** | `run_attacks(jwt_token, dmz_token)`: nested **`send_command`** (via IT `/api/submit_command`), **`send_dmz`** (direct DMZ POST), **`fire_burst`** (concurrent DMZ posts). |

### 4.9 `reports.py` — prefix `/api/v1/session`

| Route | Handler |
|-------|---------|
| `GET /report` | `get_session_report` |

Builds CSV or JSON from **`commands.log`** filtered by `dmz_session_token`, with optional fallback **`GET {dmz_base_url}/api/session/commands`**.

### 4.10 `limiter.py`

Exports **`limiter`** (`slowapi.Limiter(key_func=get_remote_address)`). Currently used on **`approval.request_write`** only (not on `main.submit_command`).

### 4.11 Scripts and tests (not mounted as routes)

| File | Role |
|------|------|
| **`trigger_rejected.py`** | Loop: POST malicious payloads to local `/api/submit_command` for Splunk / DMZ demo. |
| **`test.py`** | IT login → DMZ session GET → submit command → poll session. |
| **`test_dmz_write.py`** | Single POST to DMZ `/process_enqueue`. |

### 4.12 Config / docs artifacts

| File | Role |
|------|------|
| **`requirements.txt`** | Declared deps; runtime may also need **`pydantic-settings`**, **`python-jose`**, **`bcrypt`**, **`slowapi`**, **`python-multipart`**, etc. |
| **`.env.example`** | Template for `DMZ_BASE_URL`, JWT, DB path, rate limits. |
| **`AUTH_SETUP.md`** | Human-readable auth notes. |

---

## 5. API surface (mounted on `main:app`)

| Area | Paths | Module |
|------|-------|--------|
| Core IT API | `/api/submit_command`, `/api/login`, `/api/v1/login`, `/api/send_test_command`, `/health`, `/` | `main.py` |
| Approval & pending | `/api/v1/request_write`, `/api/v1/pending`, `/api/v1/execute_scheduled/{id}`, `/api/v1/delete_scheduled/{id}`, `/api/v1/approve/{id}`, `/api/v1/reject/{id}` | `approval.py` |
| Users | `/api/v1/users` … | `users.py` |
| Attack sim | `/api/v1/run_attack_simulation` | `attack.py` |
| Reports | `/api/v1/session/report` | `reports.py` |

---

## 6. Key workflows (concise)

### 6.1 Authentication

1. Browser: `login.html` → `POST /api/v1/login` with username/password.
2. `main.login_v1`: `verify_password` (SQLite bcrypt, else `auth.json` SHA-256).
3. IT issues JWT; IT calls DMZ `POST /api/login` → **`dmz_session_token`**.
4. Frontend stores **`jwt`**, **`dmz_session_token`**, **`username`**, **`role`** in `sessionStorage`.
5. IT API calls use **`Authorization: Bearer <jwt>`** and **`X-DMZ-Session-Token`** where implemented; DMZ direct calls use **`x-session-token`**.

### 6.2 Command submission (normal)

1. Frontend → **`POST /api/submit_command`** (with headers as above).
2. `main.submit_command`: Pydantic validation, RBAC, optional scheduled path → **`db.create_pending_command`**, else immediate **`httpx`** POST to **`UPSTREAM_URL`** (`…/process_enqueue`).
3. Logging: **`commands.log`** + Splunk HEC in success paths.

### 6.3 Scheduled commands

1. `submit_command` with **`scheduled_at`** persists row with `status='scheduled'`.
2. **`check_and_execute_scheduled_commands`** (async loop) picks due rows and POSTs to DMZ.

### 6.4 Live dashboard

Admin/User pages call **DMZ** `GET {DMZ_URL}/api/session/commands` with the DMZ session token — not the IT backend — for the table contents.

---

## 7. Operational notes

- **CORS:** Default origins include localhost frontend and the configured DMZ base URL; override with **`ALLOWED_ORIGINS`** (comma-separated).
- **Rate limiting:** **`slowapi`** on **`POST /api/v1/request_write`** only; `Request` parameter is present for SlowAPI compatibility.
- **Splunk:** HEC URL/token in `main.py` (treat as secrets in production; move to env).
- **DMZ URL changes:** Update **`DMZ_BASE_URL`** in `.env`, defaults in `config.py`, and frontend **`DMZ_URL`** in `app.js` / admin fallback string so browser-side DMZ calls stay aligned.

---

## 8. Cross-reference

| Need | Document |
|------|----------|
| Install, run servers, default accounts, troubleshooting | **`README.md`** |
| Architecture + code map + accurate auth / API summary | **`PROJECT_CONTEXT.md`** (this file) |
| Per-symbol tables mirroring this file | **`README.md` → “Project files & functions reference”** |
