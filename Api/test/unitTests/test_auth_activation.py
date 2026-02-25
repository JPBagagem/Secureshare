import pytest
from fastapi.testclient import TestClient
import uuid

from src.models.User import LoginResponse

def test_activate_user_success(client: TestClient, admin_token: LoginResponse):
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
    new_password = "new_secure_password"
    activate_data = {
        "user_name": username,
        "password": new_password,
        "one_time_password": otp,
        "assymetric_public_key": "test_key"
    }
    response = client.post("/api/auth/activate", json=activate_data)
    assert response.status_code == 200
    activated_user = response.json()
    
    assert activated_user["user_name"] == username
    assert activated_user["hash_password"] != user_data["password"]


def test_activate_user_wrong_otp(client: TestClient, admin_token: LoginResponse):
    # 1. Create User
    username = f"user_{uuid.uuid4().hex[:8]}"
    headers = {
        "Authorization": f"Bearer {admin_token.access_token}",
        "X-Role-Token": admin_token.role_tokens["ADMINISTRATOR"].signature
    }
    response = client.post("/api/users", json={"user_name": username}, headers=headers)
    assert response.status_code == 201
    
    # 2. Activate with wrong OTP
    activate_data = {
        "user_name": username,
        "password": "new_password",
        "one_time_password": "wrong_otp",
        "assymetric_public_key": "test_key"
    }
    response = client.post("/api/auth/activate", json=activate_data)
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid username or password"

def test_activate_non_existent_user(client: TestClient):
    activate_data = {
        "user_name": "non_existent_user",
        "password": "new_password",
        "one_time_password": "some_otp",
        "assymetric_public_key": "test_key"
    }
    response = client.post("/api/auth/activate", json=activate_data)
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid username or password"

def test_activate_already_activated_user(client: TestClient, admin_token: LoginResponse):
    # 1. Create User
    username = f"user_{uuid.uuid4().hex[:8]}"
    headers = {
        "Authorization": f"Bearer {admin_token.access_token}",
        "X-Role-Token": admin_token.role_tokens["ADMINISTRATOR"].signature
    }
    response = client.post("/api/users", json={"user_name": username}, headers=headers)
    user_data = response.json()
    otp = user_data["password"]

    # 2. Activate User
    activate_data = {
        "user_name": username, 
        "password": "new_password", 
        "one_time_password": otp,
        "assymetric_public_key": "test_key"
    }
    client.post("/api/auth/activate", json=activate_data)

    # 3. Activate Again
    response = client.post("/api/auth/activate", json=activate_data)
    assert response.status_code == 200
