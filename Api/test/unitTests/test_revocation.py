import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from src.main import app
from src.models.User import User, FixtureLoginResponse
from src.models.ClearanceToken import ClearanceTokens, TokenStatus
from datetime import datetime, timedelta, timezone
import jwt
from src.core.security import ALGORITHM
from src.core.settings import settings
from src.models.RoleToken import RoleToken


def test_unified_revocation(client: TestClient, session: Session, security_officer_token: FixtureLoginResponse, clearance_token):
    
    clearance_jwt, standard_user_token = clearance_token
    
    headers = {
        "Authorization": f"Bearer {security_officer_token.access_token}",
        "X-Role-Token": security_officer_token.role_tokens["SECURITY_OFFICER"].signature
    }

    # 3. Revoke Role Token
    revocation_payload = {
        "sub": str(standard_user_token.user_id),
        "type": "role",
        "iss": str(security_officer_token.user_id),
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(days=1)
    }
    revocation_jwt = jwt.encode(revocation_payload, security_officer_token.private_key, algorithm=ALGORITHM)
    
    request_body = {
        "signature": revocation_jwt,
        "revoked_at": datetime.now(timezone.utc).isoformat()
    }
    
    response = client.put(f"/api/users/{standard_user_token.user_id}/revoke/{standard_user_token.role_tokens["STANDARD_USER"].id}", json=request_body, headers=headers)
    assert response.status_code == 200
    assert response.json()["role_token"] == standard_user_token.role_tokens["STANDARD_USER"].id
    
    db_role_token = session.get(RoleToken, standard_user_token.role_tokens["STANDARD_USER"].id)
    session.refresh(db_role_token)
    assert db_role_token.status == "REVOKED"
    
    # Fetch the clearance token object from DB to get its ID
    db_clearance_token = session.exec(select(ClearanceTokens).where(ClearanceTokens.user_id == standard_user_token.user_id)).first()
    assert db_clearance_token is not None
    
    # 4. Revoke Clearance Token
    revocation_payload_clearance = {
        "sub": str(standard_user_token.user_id),
        "type": "clearance",
        "iss": str(security_officer_token.user_id),
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(days=1)
    }
    revocation_jwt_clearance = jwt.encode(revocation_payload_clearance, security_officer_token.private_key, algorithm=ALGORITHM)
    
    request_body_clearance = {
        "signature": revocation_jwt_clearance,
        "revoked_at": datetime.now(timezone.utc).isoformat()
    }
    
    response = client.put(f"/api/users/{standard_user_token.user_id}/revoke/{db_clearance_token.id}", json=request_body_clearance, headers=headers)
    assert response.status_code == 200
    # Response might be different structure, let's check DB
    
    session.refresh(db_clearance_token)
    assert db_clearance_token.token_status == TokenStatus.REVOKED.value
