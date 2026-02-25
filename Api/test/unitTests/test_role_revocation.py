import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session
from src.models.User import User, LoginResponse
from src.models.Role import Role, RoleType
from src.models.RoleToken import RoleToken
from src.core.security import create_access_token, ALGORITHM
from datetime import datetime, timezone
import jwt

def test_revoke_role_token(client: TestClient, session: Session, security_officer_token: LoginResponse, trusted_officer_token: LoginResponse):
    
    revocation_payload = {
        "sub": str(trusted_officer_token.role_tokens["TRUSTED_OFFICER"].id),
        "iss": str(security_officer_token.user_id),
        "type": "role"
    }
    revocation_signature = jwt.encode(revocation_payload, security_officer_token.private_key.encode(), algorithm=ALGORITHM)

    revocation_request = {
        "signature": revocation_signature,
        "revoked_at": datetime.now(timezone.utc).isoformat()
    }
    
    # 4. Call Endpoint
    response = client.put(
        f"/api/users/{trusted_officer_token.user_id}/revoke/{trusted_officer_token.role_tokens["TRUSTED_OFFICER"].id}",
        json=revocation_request,
        headers={
            "Authorization": f"Bearer {security_officer_token.access_token}",
            "X-Role-Token": security_officer_token.role_tokens["SECURITY_OFFICER"].signature 
        }
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["revoked_by"] == security_officer_token.user_id
    assert data["role_token"] == trusted_officer_token.role_tokens["TRUSTED_OFFICER"].id
    
    # Verify token is REVOKED
    revoked_token = session.get(RoleToken, trusted_officer_token.role_tokens["TRUSTED_OFFICER"].id)
    assert revoked_token is not None
    assert revoked_token.status == "REVOKED"


def test_revoke_role_token_invalid_token(client: TestClient, session: Session, security_officer_token: LoginResponse, trusted_officer_token: LoginResponse, auditor_token: LoginResponse):
        
    revocation_payload = {
        "sub": str(trusted_officer_token.role_tokens["TRUSTED_OFFICER"].id),
        "iss": str(security_officer_token.user_id),
        "type": "role"
    }
    revocation_signature = jwt.encode(revocation_payload, security_officer_token.private_key.encode(), algorithm=ALGORITHM)

    revocation_request = {
        "signature": revocation_signature,
        "revoked_at": datetime.now(timezone.utc).isoformat()
    }
    
    # 4. Call Endpoint
    response = client.put(
        f"/api/users/{auditor_token.user_id}/revoke/{trusted_officer_token.role_tokens["TRUSTED_OFFICER"].id}",
        json=revocation_request,
        headers={
            "Authorization": f"Bearer {security_officer_token.access_token}",
            "X-Role-Token": security_officer_token.role_tokens["SECURITY_OFFICER"].signature 
        }
    )
    
    assert response.status_code == 400
    data = response.json()
    assert data["detail"] == "Token does not belong to the specified user"
    
    # Verify token is NOT deleted (it wasn't found/revoked)
    deleted_token = session.get(RoleToken, trusted_officer_token.role_tokens["TRUSTED_OFFICER"].id)
    assert deleted_token is not None

def test_revoke_token_role_different_user_from_authorized(client: TestClient, session: Session, security_officer_token: LoginResponse, trusted_officer_token: LoginResponse, admin_token: LoginResponse):
    
    revocation_payload = {
        "sub": str(trusted_officer_token.role_tokens["TRUSTED_OFFICER"].id),
        "iss": str(security_officer_token.user_id),
        "type": "role"
    }
    revocation_signature = jwt.encode(revocation_payload, security_officer_token.private_key.encode(), algorithm=ALGORITHM)

    revocation_request = {
        "signature": revocation_signature,
        "revoked_at": datetime.now(timezone.utc).isoformat()
    }
    
    # 4. Call Endpoint
    response = client.put(
        f"/api/users/{trusted_officer_token.user_id}/revoke/{trusted_officer_token.role_tokens["TRUSTED_OFFICER"].id}",
        json=revocation_request,
        headers={
            "Authorization": f"Bearer {admin_token.access_token}",
            "X-Role-Token": trusted_officer_token.role_tokens["TRUSTED_OFFICER"].signature 
        }
    )
    
    assert response.status_code == 403
    # data = response.json()
    # assert data["detail"] == "Role token not found"
    
    # Verify token is NOT deleted (it wasn't found/revoked)
    deleted_token = session.get(RoleToken, trusted_officer_token.role_tokens["TRUSTED_OFFICER"].id)
    assert deleted_token is not None


def test_revoke_admin_role(client: TestClient, session: Session, admin_token: LoginResponse, trusted_officer_token: LoginResponse):
    
    revocation_payload = {
        "sub": str(admin_token.role_tokens["ADMINISTRATOR"].id),
        "iss": str(trusted_officer_token.user_id),
        "type": "role"
    }
    revocation_signature = jwt.encode(revocation_payload, trusted_officer_token.private_key.encode(), algorithm=ALGORITHM)

    revocation_request = {
        "signature": revocation_signature,
        "revoked_at": datetime.now(timezone.utc).isoformat()
    }
    
    # 4. Call Endpoint
    response = client.put(
        f"/api/users/{admin_token.user_id}/revoke/{admin_token.role_tokens["ADMINISTRATOR"].id}",
        json=revocation_request,
        headers={
            "Authorization": f"Bearer {trusted_officer_token.access_token}",
            "X-Role-Token": trusted_officer_token.role_tokens["TRUSTED_OFFICER"].signature 
        }
    )
    
    assert response.status_code == 403 
    
    # Verify token is NOT deleted
    deleted_token = session.get(RoleToken, admin_token.role_tokens["ADMINISTRATOR"].id)
    assert deleted_token is not None