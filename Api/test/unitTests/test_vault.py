import pytest
import base64
from fastapi.testclient import TestClient
from sqlmodel import Session
from src.models.User import User
from src.core.security import hash_password, create_access_token

@pytest.fixture(name="user_token")
def user_token_fixture(session: Session):
    hashed_password, salt = hash_password("password")
    user = User(
        user_name="vault_user",
        hash_password=hashed_password,
        salt=salt,
        is_activated=True
    )
    session.add(user)
    session.commit()
    
    token = create_access_token(data={"sub": user.user_name, "id": user.id})
    return token

def test_get_vault(client: TestClient, user_token: str):
    # 1. Use a realistic binary blob
    real_blob_bytes = b"fake_binary_blob_for_testing"
    blob_b64 = base64.b64encode(real_blob_bytes).decode()

    # 2. PUT the blob
    vault_data = {"blob": blob_b64}
    client.put("/api/users/me/vault", json=vault_data, headers={"Authorization": f"Bearer {user_token}"})

    # 3. GET the blob
    response = client.get("/api/users/me/vault", headers={"Authorization": f"Bearer {user_token}"})
    assert response.status_code == 200
    data = response.json()

    # 4. Assert the returned blob matches what was PUT
    assert "blob" in data
    assert data["blob"] == blob_b64

def test_put_vault_unauthorized(client: TestClient):
    vault_data = {"blob": "encrypted_blob_data"}
    response = client.put("/api/users/me/vault", json=vault_data)
    assert response.status_code == 401

def test_get_vault_unauthorized(client: TestClient):
    response = client.get("/api/users/me/vault")
    assert response.status_code == 401
