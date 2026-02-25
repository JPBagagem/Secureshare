import pytest
from fastapi import FastAPI, Depends, Header
from fastapi.testclient import TestClient
from sqlmodel import Session
from src.core.deps import get_current_user_clearance, get_db
from src.models.User import User
from src.models.ClearanceToken import ClearanceTokens, TokenStatus
from src.core.security import ALGORITHM
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
import uuid

# Setup a test app to test the dependency
mock_app = FastAPI()

@mock_app.get("/test-clearance")
def protected_route(clearance:  ClearanceTokens| None = Depends(get_current_user_clearance)):
    return clearance

@pytest.fixture(name="client")
def client_fixture(session: Session):
    def get_session_override():
        return session
    
    mock_app.dependency_overrides[get_db] = get_session_override
    return TestClient(mock_app)

@pytest.fixture(name="so_keys")
def so_keys_fixture():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_key, pem_public.decode()

def test_get_current_user_clearance_success(client: TestClient, session: Session, so_keys):
    private_key, public_key_pem = so_keys
    
    # 1. Setup Users

    so_name = f"so_clearance_test_{uuid.uuid4().hex[:8]}"
    target_name = f"target_clearance_test_{uuid.uuid4().hex[:8]}"
    
    so_user = User(user_name=so_name, assymetric_public_key=public_key_pem, hash_password="hashed_pw")
    session.add(so_user)
    
    target_user = User(user_name=target_name, hash_password="hashed_pw")
    session.add(target_user)
    session.commit()
    session.refresh(so_user)
    session.refresh(target_user)
    
    # Mock get_current_user to return target_user
    # We need to override get_current_user because the dependency uses it
    from src.core.deps import get_current_user
    mock_app.dependency_overrides[get_current_user] = lambda: target_user
    
    # 2. Create Clearance Token
    issued_at = datetime.now(timezone.utc)
    expired_at = datetime.now(timezone.utc) + timedelta(days=1)
    
    payload = {
        "sub": str(target_user.id),
        "iss": str(so_user.id),
        "clearance_id": 101,
        "iat": issued_at,
        "exp": expired_at
    }
    token_jwt = jwt.encode(payload, private_key, algorithm=ALGORITHM)
    
    clearance_token = ClearanceTokens(
        user_id=target_user.id,
        clearance_id=101,
        issued_by=so_user.id,
        issued_at=issued_at,
        signature=token_jwt,
        token_status=TokenStatus.ACTIVE.value
    )
    session.add(clearance_token)
    session.commit()
    
    # 3. Test Endpoint
    response = client.get("/test-clearance", headers={"X-Clearance-Token": token_jwt})
    assert response.status_code == 200
    data = response.json()
    print(data)
    assert  data["clearance_id"] == 101

def test_get_current_user_clearance_revoked(client: TestClient, session: Session, so_keys):
    private_key, public_key_pem = so_keys
    
    # 1. Setup Users
    so_name = f"so_clearance_revoked_{uuid.uuid4().hex[:8]}"
    target_name = f"target_clearance_revoked_{uuid.uuid4().hex[:8]}"
    
    so_user = User(user_name=so_name, assymetric_public_key=public_key_pem, hash_password="hashed_pw")
    session.add(so_user)
    
    target_user = User(user_name=target_name, hash_password="hashed_pw")
    session.add(target_user)
    session.commit()
    session.refresh(so_user)
    session.refresh(target_user)
    
    from src.core.deps import get_current_user
    mock_app.dependency_overrides[get_current_user] = lambda: target_user
    
    # 2. Create Revoked Clearance Token
    payload = {
        "sub": str(target_user.id),
        "iss": str(so_user.id),
        "clearance_id": 102,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(days=1)
    }
    token_jwt = jwt.encode(payload, private_key, algorithm=ALGORITHM)
    
    clearance_token = ClearanceTokens(
        user_id=target_user.id,
        clearance_id=102,
        issued_by=so_user.id,
        issued_at=datetime.now(timezone.utc),
        signature=token_jwt,
        token_status=TokenStatus.REVOKED.value
    )
    session.add(clearance_token)
    session.commit()
    
    # 3. Test Endpoint
    response = client.get("/test-clearance", headers={"X-Clearance-Token": token_jwt})
    assert response.status_code == 200
    assert response.json() == None

def test_get_current_user_clearance_invalid_signature(client: TestClient, session: Session, so_keys):
    private_key, public_key_pem = so_keys
    
    # 1. Setup Users
    so_name = f"so_clearance_invalid_{uuid.uuid4().hex[:8]}"
    target_name = f"target_clearance_invalid_{uuid.uuid4().hex[:8]}"
    
    so_user = User(user_name=so_name, assymetric_public_key=public_key_pem, hash_password="hashed_pw")
    session.add(so_user)
    
    target_user = User(user_name=target_name, hash_password="hashed_pw")
    session.add(target_user)
    session.commit()
    session.refresh(so_user)
    session.refresh(target_user)
    
    from src.core.deps import get_current_user
    mock_app.dependency_overrides[get_current_user] = lambda: target_user
    
    # 2. Create Token with DIFFERENT key (simulating invalid signature)
    other_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_pem = other_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    payload = {
        "sub": str(target_user.id),
        "iss": str(so_user.id),
        "clearance_id": 103,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(days=1)
    }
    token_jwt = jwt.encode(payload, other_pem.decode(), algorithm=ALGORITHM)
    
    # 3. Test Endpoint
    response = client.get("/test-clearance", headers={"X-Clearance-Token": token_jwt})
    assert response.status_code == 200
    assert response.json() == None
