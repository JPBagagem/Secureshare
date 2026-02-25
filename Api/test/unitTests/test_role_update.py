import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from src.main import app
from src.models.User import User, FixtureLoginResponse
from src.models.Role import Role, RoleType
from src.models.RoleToken import RoleToken, RoleTokenCreate, RoleTokenResponse
from src.core.security import hash_password
from datetime import datetime, timedelta, timezone
import jwt
from src.core.security import ALGORITHM
from src.core.settings import settings
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization



def test_role_update_flow(client: TestClient, session: Session, admin_token: FixtureLoginResponse, trusted_officer_token: FixtureLoginResponse):
    
    private_key = admin_token.private_key
    
    issued_at = datetime.now(timezone.utc)
    expired_at = datetime.now(timezone.utc) + timedelta(days=365)
    
    # Create Target User
    hashed_pwd_target, salt_target = hash_password("targetpass")
    target_user = User(
        user_name="target",
        hash_password=hashed_pwd_target,
        salt=salt_target,
        is_activated=True
    )
    session.add(target_user)
    session.commit()
    session.refresh(target_user)
    
    # Login as Admin to get token
    headers = {"Authorization": f"Bearer {admin_token.access_token}", "X-Role-Token": admin_token.role_tokens["ADMINISTRATOR"].signature}
    
    # Prepare Signed Payload for assigning Trusted Officer role to target_user
    issued_at = datetime.now(timezone.utc)
    expired_at = datetime.now(timezone.utc) + timedelta(days=365)
    
    token_payload = {
        "sub": str(target_user.id),
        "role_type": "TRUSTED_OFFICER",
        "dept_id": None,
        "iss": str(admin_token.user_id),
        "iat": issued_at,
        "exp": expired_at
    }
    
    signature_jwt = jwt.encode(token_payload, private_key, algorithm=ALGORITHM)
    
    payload = {
        "signature": signature_jwt,
    }
    
    # Call Endpoint
    response = client.put(f"/api/users/{target_user.id}/role", json=payload, headers=headers)
    
    # Verify Success
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["user_id"] == target_user.id
    trusted_officer_role = session.exec(select(Role).where(Role.role == RoleType.TRUSTED_OFFICER)).first()
    assert data["role_id"] == trusted_officer_role.id
    assert data["signature"] == signature_jwt
    
    # Verify DB
    db_token = session.exec(select(RoleToken).where(RoleToken.user_id == target_user.id).where(RoleToken.role_id == trusted_officer_role.id)).first()
    assert db_token is not None
    assert db_token.issued_by == admin_token.user_id

def test_role_update_invalid_signature(client: TestClient, session: Session, admin_keys, admin_token):
    # Reuse setup logic or create fixtures if this was a larger suite. 
    # For brevity, I'll do a quick setup here or rely on clean DB state if pytest-asyncio/session scope handles it.
    # Assuming function scope for session, so we need to recreate data.
    
    private_key, public_key_pem = admin_keys
    
    # Setup Admin
    admin_role = session.exec(select(Role).where(Role.role == RoleType.ADMINISTRATOR)).first()
    
    hashed_pwd, salt = hash_password("adminpass")
    admin_user = User(
        user_name="admin_fail",
        hash_password=hashed_pwd,
        salt=salt,
        is_activated=True,
        assymetric_public_key=public_key_pem
    )
    session.add(admin_user)
    session.commit()
    session.refresh(admin_user)
    
    issued_at = datetime.now(timezone.utc)
    expired_at = datetime.now(timezone.utc) + timedelta(days=365)
    
    role_token_payload = {
        "sub": str(admin_user.id),
        "role_id": admin_role.id,
        "dept_id": None,
        "iss": str(admin_user.id),
        "iat": issued_at,
        "exp": expired_at
    }
    
    role_token_jwt = jwt.encode(role_token_payload, private_key, algorithm=ALGORITHM)

    admin_role_token = RoleToken(
        user_id=admin_user.id,
        role_id=admin_role.id,
        issued_by=admin_user.id,
        issued_at=issued_at,
        expired_at=expired_at,
        signature=role_token_jwt,
        token_data="setup"
    )
    session.add(admin_role_token)
    session.commit()
    
    # Login
    login_response = client.post("/api/auth/login", json={"user_name": "admin_fail", "password": "adminpass"})
    data = login_response.json()
    token = data["access_token"]
    role_sig = data["role_tokens"]["ADMINISTRATOR"]["signature"]
    headers = {"Authorization": f"Bearer {token}", "X-Role-Token": role_sig}
    
    # Prepare Payload with INVALID signature
    payload = {
        "user_id": admin_user.id, # Assigning to self for simplicity
        "role_id": admin_role.id,
        "expired_at": datetime.now(timezone.utc).isoformat(),
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "issued_by": admin_user.id,
        "signature": "invalid_base64_signature",
        "token_data": "some_data"
    }
    
    response = client.put(f"/api/users/{admin_user.id}/role", json=payload, headers=headers)
    assert response.status_code == 400
    assert "Invalid token" in response.text

def test_create_user_rbac(client: TestClient, session: Session):
    # 1. Create Standard User (No Admin Role)
    hashed_pwd, salt = hash_password("userpass")
    user = User(user_name="standard", hash_password=hashed_pwd, salt=salt, is_activated=True)
    session.add(user)
    session.commit()
    
    # Login
    login_response = client.post("/api/auth/login", json={"user_name": "standard", "password": "userpass"})
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # 2. Try to create a user
    new_user_payload = {"user_name": "new_user"}
    response = client.post("/api/users", json=new_user_payload, headers=headers)
    
    # 3. Assert Forbidden
    assert response.status_code == 403
    assert "Not authorized" in response.text

def test_create_user_admin_success(client: TestClient, session: Session, admin_token):
    # 1. Setup Admin User and Role
    admin_role = session.exec(select(Role).where(Role.role == RoleType.ADMINISTRATOR)).first()
    
    hashed_pwd, salt = hash_password("adminpass")
    admin_user = User(
        user_name="admin_create",
        hash_password=hashed_pwd,
        salt=salt,
        is_activated=True
    )
    session.add(admin_user)
    session.commit()
    session.refresh(admin_user)
    
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    
    # Update admin user with this key
    admin_user.assymetric_public_key = pem_public
    session.add(admin_user)
    session.commit()
    session.refresh(admin_user)
    
    issued_at = datetime.now(timezone.utc)
    expired_at = datetime.now(timezone.utc) + timedelta(days=365)
    
    role_token_payload = {
        "sub": str(admin_user.id),
        "role_id": admin_role.id,
        "dept_id": None,
        "iss": str(admin_user.id),
        "iat": issued_at,
        "exp": expired_at
    }
    
    role_token_jwt = jwt.encode(role_token_payload, private_key, algorithm=ALGORITHM)

    admin_role_token = RoleToken(
        user_id=admin_user.id,
        role_id=admin_role.id,
        issued_by=admin_user.id,
        issued_at=issued_at,
        expired_at=expired_at,
        signature=role_token_jwt,
        token_data="setup"
    )
    session.add(admin_role_token)
    session.commit()
    
    # 2. Login as Admin
    login_response = client.post("/api/auth/login", json={"user_name": "admin_create", "password": "adminpass"})
    assert login_response.status_code == 200
    data = login_response.json()
    token = data["access_token"]
    role_sig = data["role_tokens"]["ADMINISTRATOR"]["signature"]
    headers = {"Authorization": f"Bearer {token}", "X-Role-Token": role_sig}
    
    # 3. Create User
    new_user_payload = {"user_name": "new_created_user"}
    response = client.post("/api/users", json=new_user_payload, headers=headers)
    
    # 4. Verify Success
    assert response.status_code == 201
    data = response.json()
    assert data["user_name"] == "new_created_user"
    assert "password" in data # Should return the raw password
