import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from src.main import app
from src.models.User import User
from src.models.RevokedToken import RevokedToken
from src.core.security import hash_password, create_access_token
from datetime import datetime, timedelta, timezone

def test_logout_success(client: TestClient, session: Session):
    # Create user
    hashed_password, salt = hash_password("testpass")
    user = User(
        user_name="logout_test_user",
        hash_password=hashed_password,
        salt=salt,
        is_activated=True
    )
    session.add(user)
    session.commit()
    
    # Login to get token
    response = client.post(
        "/api/auth/login",
        json={"user_name": "logout_test_user", "password": "testpass"}
    )
    token = response.json()["access_token"]
    
    # Logout
    response = client.post(
        "/api/auth/logout",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Successfully logged out"
    
    # Verify token is in revoked_tokens
    revoked = session.exec(select(RevokedToken).where(RevokedToken.token == token)).first()
    assert revoked is not None

def test_access_revoked_token(client: TestClient, session: Session):
    # Create user
    hashed_password, salt = hash_password("testpass")
    user = User(
        user_name="revoked_test_user",
        hash_password=hashed_password,
        salt=salt,
        is_activated=True
    )
    session.add(user)
    session.commit()
    
    # Login to get token
    response = client.post(
        "/api/auth/login",
        json={"user_name": "revoked_test_user", "password": "testpass"}
    )
    token = response.json()["access_token"]
    
    # Logout
    client.post(
        "/api/auth/logout",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    # Try to access protected endpoint
    response = client.post(
        "/api/users",
        json={"user_name": "should_fail"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Token has been revoked"

def test_logout_unauthenticated(client: TestClient):
    response = client.post("/api/auth/logout")
    assert response.status_code == 401

def test_logout_twice(client: TestClient, session: Session):
    # Create user
    hashed_password, salt = hash_password("testpass")
    user = User(
        user_name="double_logout_user",
        hash_password=hashed_password,
        salt=salt,
        is_activated=True
    )
    session.add(user)
    session.commit()
    
    # Login to get token
    response = client.post(
        "/api/auth/login",
        json={"user_name": "double_logout_user", "password": "testpass"}
    )
    token = response.json()["access_token"]
    
    # First Logout
    response = client.post(
        "/api/auth/logout",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    
    # Second Logout
    response = client.post(
        "/api/auth/logout",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Token has been revoked"

def test_logout_cleans_expired_tokens(client: TestClient, session: Session):
    # 1. Insert an expired token manually
    expired_token = RevokedToken(
        token="expired_token_string",
        expires_at=datetime.now(timezone.utc) - timedelta(days=1)
    )
    session.add(expired_token)
    
    # 2. Insert a valid (revoked) token manually
    valid_revoked_token = RevokedToken(
        token="valid_revoked_token_string",
        expires_at=datetime.now(timezone.utc) + timedelta(days=1)
    )
    session.add(valid_revoked_token)
    session.commit()
    
    # 3. Perform a normal logout with a new user
    hashed_password, salt = hash_password("testpass")
    user = User(
        user_name="cleanup_test_user",
        hash_password=hashed_password,
        salt=salt,
        is_activated=True
    )
    session.add(user)
    session.commit()
    
    response = client.post(
        "/api/auth/login",
        json={"user_name": "cleanup_test_user", "password": "testpass"}
    )
    token = response.json()["access_token"]
    
    client.post(
        "/api/auth/logout",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    # 4. Verify results
    # Expired token should be gone
    assert session.exec(select(RevokedToken).where(RevokedToken.token == "expired_token_string")).first() is None
    
    # Valid revoked token should still be there
    assert session.exec(select(RevokedToken).where(RevokedToken.token == "valid_revoked_token_string")).first() is not None
    
    # New token should be there
    assert session.exec(select(RevokedToken).where(RevokedToken.token == token)).first() is not None
