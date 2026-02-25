import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session
from src.models.User import User, LoginResponse
from src.models.RoleToken import RoleToken
from src.core.security import create_access_token, ALGORITHM

def test_delete_user_success(client: TestClient, session: Session, admin_token: LoginResponse, standard_user_token: LoginResponse):
    
    response = client.delete(
        f"/api/users/{standard_user_token.user_id}",
        headers = {
            "Authorization": f"Bearer {admin_token.access_token}",
            "X-Role-Token": admin_token.role_tokens["ADMINISTRATOR"].signature
        }
    )
    
    assert response.status_code == 204
    
    # Verify user is deleted
    deleted_user = session.get(User, standard_user_token.user_id)
    assert deleted_user is None

def test_delete_user_not_found(client: TestClient, session: Session, admin_token: LoginResponse):
    
    response = client.delete(
        "/api/users/999999",
        headers = {
            "Authorization": f"Bearer {admin_token.access_token}",
            "X-Role-Token": admin_token.role_tokens["ADMINISTRATOR"].signature
        }
    )
    
    assert response.status_code == 404

def test_delete_user_with_role_token_different_from_authorized(client: TestClient, session: Session, admin_token: LoginResponse, standard_user_token: LoginResponse):
    
    response = client.delete(
        f"/api/users/{standard_user_token.user_id}",
        headers = {
            "Authorization": f"Bearer {standard_user_token.access_token}",
            "X-Role-Token": admin_token.role_tokens["ADMINISTRATOR"].signature
        }
    )
    
    assert response.status_code == 403

def test_delete_user_unauthorized(client: TestClient, session: Session, admin_token: LoginResponse, standard_user_token: LoginResponse):
    
    response = client.delete(
        f"/api/users/{standard_user_token.user_id}",
        headers={
            "Authorization": f"Bearer {admin_token.access_token}"
        }
    )
    
    assert response.status_code == 403


def test_delete_user_invalid_role_token(client: TestClient, session: Session, admin_token: LoginResponse, standard_user_token: LoginResponse):
    
    response = client.delete(
        f"/api/users/{standard_user_token.user_id}",
        headers={
            "Authorization": f"Bearer {admin_token.access_token}",
            "X-Role-Token": standard_user_token.role_tokens["STANDARD_USER"].signature
        }
    )
    
    assert response.status_code == 403
