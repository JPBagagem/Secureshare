import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session
from src.main import app
from src.models.User import User
from src.core.security import hash_password
import uuid
import time


def test_login_success(client: TestClient, session: Session):
    # Create a user
    hashed_password, salt = hash_password("password123")
    user = User(
        user_name="test_login_user",
        hash_password=hashed_password,
        salt=salt,
        is_activated=True
    )
    session.add(user)
    session.commit()

    response = client.post(
        "/api/auth/login",
        json={"user_name": "test_login_user", "password": "password123"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "role_tokens" in data
    assert isinstance(data["role_tokens"], dict)
    assert "clearance_tokens" in data
    assert isinstance(data["clearance_tokens"], list)

def test_login_invalid_password(client: TestClient, session: Session):
    # Create a user
    hashed_password, salt = hash_password("password123")
    user = User(
        user_name="test_login_fail",
        hash_password=hashed_password,
        salt=salt,
        is_activated=True
    )
    session.add(user)
    session.commit()

    response = client.post(
        "/api/auth/login",
        json={"user_name": "test_login_fail", "password": "wrongpassword"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect username or password"

def test_login_invalid_username(client: TestClient):
    response = client.post(
        "/api/auth/login",
        json={"user_name": "nonexistent", "password": "password123"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect username or password"

from src.models.User import LoginResponse

def test_login_updates_last_login(client: TestClient, admin_token: LoginResponse):
    # 1. Create User
    username = f"user_{uuid.uuid4().hex[:8]}"
    headers = {
        "Authorization": f"Bearer {admin_token.access_token}",
        "X-Role-Token": admin_token.role_tokens["ADMINISTRATOR"].signature
    }
    response = client.post("/api/users", json={"user_name": username}, headers=headers)
    assert response.status_code == 201
    user_data = response.json()
    otp = user_data["password"]
    
    # 2. Activate User
    password = "secure_password"
    activate_data = {
        "user_name": username,
        "password": password,
        "one_time_password": otp,
        "assymetric_public_key": "test_key"
    }
    response = client.post("/api/auth/activate", json=activate_data)
    assert response.status_code == 200
    
    # 3. Login first time
    login_data = {
        "user_name": username,
        "password": password
    }
    response = client.post("/api/auth/login", json=login_data)
    assert response.status_code == 200
    token1 = response.json()["access_token"]
    
    # 4. Get last_login
    response = client.get("/api/user/me/info", headers={"Authorization": f"Bearer {token1}"})
    assert response.status_code == 200
    last_login_1 = response.json()["last_login"]
    
    # Wait a bit to ensure timestamp difference
    time.sleep(1.1)
    
    # 5. Login second time
    response = client.post("/api/auth/login", json=login_data)
    assert response.status_code == 200
    token2 = response.json()["access_token"]
    
    # 6. Get last_login again
    response = client.get("/api/user/me/info", headers={"Authorization": f"Bearer {token2}"})
    assert response.status_code == 200
    last_login_2 = response.json()["last_login"]
    
    # 7. Verify it changed
    assert last_login_1 != last_login_2
