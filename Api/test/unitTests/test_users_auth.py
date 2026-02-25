import pytest
from fastapi.testclient import TestClient
from src.main import app
from src.models.User import User, LoginResponse
from src.core.security import hash_password, create_access_token
from src.models.Role import Role
from src.models.RoleToken import RoleToken
from src.core.security import ALGORITHM


def test_create_user_no_auth(client: TestClient):
    response = client.post(
        "/api/users",
        json={"user_name": "new_user"}
    )
    assert response.status_code == 401

def test_create_user_with_auth(client: TestClient, admin_token: LoginResponse):
    response = client.post(
        "/api/users",
        json={"user_name": "new_user_created"},
        headers={
            "Authorization": f"Bearer {admin_token.access_token}", 
            "X-Role-Token": admin_token.role_tokens["ADMINISTRATOR"].signature
        }
    )
    assert response.status_code == 201
    data = response.json()
    assert data["user_name"] == "new_user_created"
    assert "password" in data
