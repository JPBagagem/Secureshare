import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from src.main import app
from src.models.User import User, FixtureLoginResponse
from src.models.Role import Role, RoleType
from src.models.Clearance import Clearance
from src.models.Department import Department
from src.models.ClearanceToken import ClearanceTokens, ClearanceTokenResponse
from src.core.security import hash_password, create_access_token
from datetime import datetime, timedelta, timezone
import jwt
from src.core.security import ALGORITHM
from src.core.settings import settings


def test_clearance_flow(client: TestClient, session: Session, security_officer_token: FixtureLoginResponse, standard_user_token: FixtureLoginResponse):
    
    # Create Clearance and Department
    clearance = Clearance(name="TopSecret")
    session.add(clearance)
    department = Department(name="Engineering", created_at=datetime.now(), created_by=security_officer_token.user_id)
    session.add(department)
    session.commit()
    session.refresh(clearance)
    session.refresh(department)
    
    headers = {
        "Authorization": f"Bearer {security_officer_token.access_token}",
        "X-Role-Token": security_officer_token.role_tokens["SECURITY_OFFICER"].signature
    }
    
    # 2. Prepare Signed Clearance Token (JWT)
    issued_at = datetime.now(timezone.utc)
    expired_at = datetime.now(timezone.utc) + timedelta(days=365)
    
    clearance_payload = {
        "sub": str(standard_user_token.user_id),
        "clearance_type": clearance.name,
        "dept_ids": [department.id],
        "iss": str(security_officer_token.user_id),
        "iat": issued_at,
        "exp": expired_at
    }
    
    clearance_jwt = jwt.encode(clearance_payload, security_officer_token.private_key, algorithm=ALGORITHM)
    
    payload = {
        "token": clearance_jwt
    }
    
    # 3. Call Endpoint
    response = client.put(f"/api/users/{standard_user_token.user_id}/clearance", json=payload, headers=headers)
    
    # 4. Verify Success
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["user_id"] == standard_user_token.user_id
    assert data["clearance_id"] == clearance.id
    assert data["departments"] == [department.id]
    assert data["signature"] == clearance_jwt
    
    # Verify DB
    db_token = session.exec(select(ClearanceTokens).where(
        ClearanceTokens.user_id == standard_user_token.user_id,
        ClearanceTokens.clearance_id == clearance.id
    )).first()
    assert db_token is not None
    assert db_token.issued_by == security_officer_token.user_id
    
    # 5. Verify Get Clearance
    response = client.get(f"/api/users/{standard_user_token.user_id}/clearance", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 1
    
    found = False
    for token in data:
        if token["clearance_id"] == clearance.id:
            found = True
            break
    assert found