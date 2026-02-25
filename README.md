[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/zUSHElJ8)

# SecureShare

A secure file sharing platform implementing **Multi-Level Security (MLS)** with the **Bell-LaPadula model**, **Role-Based Access Control (RBAC)**, and end-to-end encryption.

## 🔐 Security Features

### Multi-Level Security (Bell-LaPadula Model)
- **Clearance Levels**: `UNCLASSIFIED` → `CONFIDENTIAL` → `SECRET` → `TOP_SECRET`
- **No Read Up**: Users cannot read files above their clearance level
- **No Write Down**: Users cannot write files below their clearance level (prevents information leakage)
- **Department-Based Access**: Files are associated with departments; users need clearance tokens for specific departments

### Role-Based Access Control (RBAC)
| Role | Description |
|------|-------------|
| `ADMINISTRATOR` | Full system administration |
| `SECURITY_OFFICER` | Manages security policies |
| `TRUSTED_OFFICER` | Can bypass MLS with documented reason |
| `STANDARD_USER` | Normal file operations |
| `AUDITOR` | Access to audit logs |

### Encryption
- **File Encryption**: AES-256-GCM for symmetric encryption
- **Key Wrapping**: RSA-OAEP with SHA-256 for encrypting AES keys
- **Password Hashing**: Argon2id (memory-hard KDF)
- **JWT Tokens**: RS256 (RSA + SHA-256) for authentication

### Audit Logging
- Blockchain-style linked log entries (each log contains hash of previous log)
- Tamper detection on retrieval
- All file operations logged with user ID and timestamps

---

## 📁 Project Structure

```
├── Api/                          # Backend API
│   ├── src/
│   │   ├── core/                 # Core functionality
│   │   │   ├── db.py             # Database initialization
│   │   │   ├── deps.py           # Dependency injection
│   │   │   ├── security.py       # Password hashing, JWT, signatures
│   │   │   └── settings.py       # Configuration
│   │   ├── models/               # SQLModel database models
│   │   │   ├── User.py           # User accounts
│   │   │   ├── File.py           # File metadata
│   │   │   ├── Role.py           # RBAC roles
│   │   │   ├── RoleToken.py      # Role assignments
│   │   │   ├── Clearance.py      # Security clearance levels
│   │   │   ├── ClearanceToken.py # User clearance assignments
│   │   │   ├── Department.py     # Organizational departments
│   │   │   ├── EncryptedFileKeys.py # Shared file keys
│   │   │   └── Logs.py           # Audit log entries
│   │   ├── router/               # API endpoints
│   │   │   ├── authentication.py # Login/logout
│   │   │   ├── users.py          # User management
│   │   │   ├── fileTransfer.py   # File upload/download/share
│   │   │   ├── DepartmentRouter.py # Department management
│   │   │   └── audit_log_router.py # Audit log access
│   │   ├── services/             # Business logic
│   │   │   ├── FileService.py    # File operations + MLS enforcement
│   │   │   ├── UserService.py    # User management
│   │   │   └── LogService.py     # Audit logging
│   │   └── main.py               # FastAPI application
│   └── test/                     # Unit tests
├── simpleUi.py                   # CLI client
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.12+
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

### Installation

```bash
cd Api

# Using uv (recommended)
uv sync

# Or using pip
pip install -e .
```

### Running the API

```bash
cd Api
source .venv/bin/activate
uvicorn src.main:app --reload
```

The API will be available at `http://localhost:8000` with docs at `/api/docs`.

### Running with Docker

```bash
cd Api
docker-compose up --build
```

### Running Tests

```bash
cd Api

# Using uv (recommended)
uv run pytest test/unitTests/ -v

# Or using pip
source .venv/bin/activate
python -m pytest test/unitTests/ -v
```

---

## 📡 API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Login with username/password |
| POST | `/api/auth/logout` | Invalidate current token |
| POST | `/api/auth/activate` | Activate user account with public key |

### Users
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/users/` | Create new user |
| GET | `/api/users/` | List all users |
| DELETE | `/api/users/{id}` | Delete user |
| GET | `/api/users/{id}/key` | Get user's public key |
| PUT | `/api/users/me/vault` | Update user vault |
| GET | `/api/users/me/vault` | Get user vault |
| PUT | `/api/users/{id}/role` | Assign role to user |
| PUT | `/api/users/{id}/revoke/{token_id}` | Revoke role/clearance |
| GET | `/api/users/{id}/clearance` | Get user clearance tokens |
| PUT | `/api/users/{id}/clearance` | Add user clearance token |

### User Profile
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/user/me/info` | Get current user info |
| POST | `/api/user/me/info` | Update current user info |

### File Transfers
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/transfers/` | Upload encrypted file |
| GET | `/api/transfers/` | List user's files (owned + shared) |
| GET | `/api/transfers/{file_uid}` | Get file metadata |
| DELETE | `/api/transfers/{file_uid}` | Delete file |
| POST | `/api/transfers/share/` | Share file with another user |
| GET | `/api/download/{file_uid}` | Download encrypted file |

### Departments
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/departments/` | List departments |
| POST | `/api/departments/` | Create department (admin only) |
| DELETE | `/api/departments/{id}` | Delete department (admin only) |

### Audit
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/audit/logs` | Retrieve audit logs (auditor only) |

---

## 💻 CLI Client Usage

The `simpleUi.py` provides a command-line interface for interacting with the API.

> **Note**: The CLI client is configured to communicate via HTTPS at `https://localhost/api`. Ensure you are running the API with Docker (which provides the Nginx reverse proxy) to use the CLI client, or update the `BASE_URL` in `simpleUi.py` to match your local server (e.g., `http://localhost:8000/api`).

```bash
python3 simpleUi.py
```

### Main Features
1. **User Management**: Login, logout, view info, activate accounts
2. **File Operations**: Upload, download, list, delete, share files
3. **Department Management**: View, create, delete departments
4. **Security Management**: Assign roles, issue clearance tokens, revoke access
5. **Audit**: View and sign audit logs

### File Upload Flow
1. User provides file path, clearance level, and department IDs
2. File is encrypted locally with AES-256-GCM
3. AES key is encrypted with user's RSA public key
4. Encrypted file + wrapped key sent to server

### File Sharing Flow
1. Owner decrypts AES key with their private key
2. Re-encrypts AES key with recipient's public key
3. Server stores the re-encrypted key for recipient

---

## 🔒 Security Model

### File Upload (Write)
```
User Clearance ≥ File Classification (No Write Down)
User must have role token for target department
Trusted Officer can bypass with documented reason
```

### File Download (Read)
```
User Clearance ≥ File Classification (No Read Up)
User must have clearance for all file departments
Private files require explicit share OR ownership
```

### Audit Trail
```
Each log entry contains:
- Action type
- Timestamp
- User ID
- Description
- Previous log hash (blockchain-style linking)
- Current hash (SHA-256)
```

---

## 🧪 Test Coverage

The test suite covers:
- ✅ User authentication (login, logout, token revocation)
- ✅ User management (create, activate, update)
- ✅ Bell-LaPadula enforcement (no read up, no write down)
- ✅ File upload with clearance validation
- ✅ File sharing between users
- ✅ Department-based access control
- ✅ Trusted Officer bypass with reason
- ✅ Role-based permissions (admin, auditor, etc.)

---

## 👥 Authors

- **119636**
- **120141**

