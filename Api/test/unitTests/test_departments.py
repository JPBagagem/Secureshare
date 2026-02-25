import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from src.main import app
from src.models.User import User
from src.models.Role import Role, RoleType
from src.models.RoleToken import RoleToken
from src.models.Department import Department
from src.core.security import hash_password, create_access_token
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
from src.core.security import ALGORITHM

def test_admin_can_create_department(client: TestClient, admin_token):
    # -----------------------------
    # STEP 1: Use admin_token headers
    # -----------------------------
    headers = {
        "Authorization": f"Bearer {admin_token.access_token}",
        "X-Role-Token": admin_token.role_tokens["ADMINISTRATOR"].signature
    }

    # -----------------------------
    # STEP 4: Add a department using admin user
    # -----------------------------
    dep_name = "Research_New"
    dep_payload = {"name": dep_name}
    resp = client.post("/api/departments/", headers=headers, json=dep_payload)
    assert resp.status_code == 200
    print(resp.json())

    # -----------------------------
    # STEP 5: List all departments and assert the new one exists
    # -----------------------------
    resp = client.get("/api/departments/", headers=headers)
    assert resp.status_code == 200
    print(resp.json())
    print(dep_name)
    dep_names = [d["name"] for d in resp.json()]
    assert dep_name in dep_names

    print(f"Department '{dep_name}' successfully created by admin user with id .")

def test_user_without_role_cannot_create_department(client: TestClient, session: Session):
    # -----------------------------
    # STEP 1: Create a normal user (no roles)
    # -----------------------------
    priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = priv_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    hashed, salt = hash_password("password123")
    user = User(
        user_name="user_no_role",
        hash_password=hashed,
        salt=salt,
        assymetric_public_key=pub_pem.decode(),
        is_activated=True
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    jwt_token = create_access_token({"sub": user.user_name, "id": user.id})
    headers = {"Authorization": f"Bearer {jwt_token}"}

    # -----------------------------
    # STEP 2: Attempt to add a department → should fail
    # -----------------------------
    dep_name = "Finance"
    dep_payload = {"name": dep_name}
    resp = client.post("/api/departments/", headers=headers, json=dep_payload)
    assert resp.status_code == 403
    print("User without any role cannot create department → PASSED")


def test_user_with_normal_role_cannot_create_department(client: TestClient, session: Session, standard_user_token):
    # -----------------------------
    # STEP 1: Use standard_user_token headers
    # -----------------------------
    headers = {
        "Authorization": f"Bearer {standard_user_token.access_token}",
        "X-Role-Token": standard_user_token.role_tokens["STANDARD_USER"].signature
    }

    # -----------------------------
    # STEP 4: Attempt to add a department → should fail
    # -----------------------------
    dep_name = "Marketing"
    dep_payload = {"name": dep_name}
    resp = client.post("/api/departments/", headers=headers, json=dep_payload)
    assert resp.status_code == 403
    print("User with normal role cannot create department → PASSED")


def test_admin_can_delete_department(client: TestClient, session: Session, admin_token):
    # -----------------------------
    # STEP 1: Use admin_token headers
    # -----------------------------
    headers = {
        "Authorization": f"Bearer {admin_token.access_token}",
        "X-Role-Token": admin_token.role_tokens["ADMINISTRATOR"].signature
    }

    # -----------------------------
    # STEP 3: Create a department
    # -----------------------------
    
    # Fetch admin user from DB (assuming admin_token created "admin_test_fixture")
    admin_user = session.exec(select(User).where(User.user_name == "admin_fixture")).first()
    
    dept = Department(name="TempDept", created_at=datetime.now(timezone.utc), created_by=admin_user.id)
    session.add(dept)
    session.commit()
    session.refresh(dept)

    # -----------------------------
    # STEP 4: Admin deletes the department
    # -----------------------------
    resp = client.delete(f"/api/departments/{dept.id}", headers=headers)
    assert resp.status_code == 200
    print("Admin successfully deleted department → PASSED")


def test_user_without_roles_cannot_delete_department(client: TestClient, session: Session):
    # -----------------------------
    # STEP 1: Create normal user
    # -----------------------------
    priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = priv_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    hashed, salt = hash_password("password123")
    user = User(
        user_name="user_no_roles_delete",
        hash_password=hashed,
        salt=salt,
        assymetric_public_key=pub_pem.decode(),
        is_activated=True
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    # -----------------------------
    # STEP 2: Create a department (admin creates)
    # -----------------------------
    dept = Department(name="NoRoleDept", created_at=datetime.now(timezone.utc), created_by=3)
    session.add(dept)
    session.commit()
    session.refresh(dept)

    # -----------------------------
    # STEP 3: Attempt delete → should fail
    # -----------------------------
    jwt_token = create_access_token({"sub": user.user_name, "id": user.id})
    headers = {"Authorization": f"Bearer {jwt_token}"}
    resp = client.delete(f"/api/departments/{dept.id}", headers=headers)
    assert resp.status_code in (403, 404)
    print("User without roles cannot delete department → PASSED")


def test_user_with_normal_role_cannot_delete_department(client: TestClient, session: Session, standard_user_token):
    # -----------------------------
    # STEP 1: Use standard_user_token headers
    # -----------------------------
    headers = {
        "Authorization": f"Bearer {standard_user_token.access_token}",
        "X-Role-Token": standard_user_token.role_tokens["STANDARD_USER"].signature
    }

    # -----------------------------
    # STEP 4: Create a department (admin creates)
    # -----------------------------
    # Just create a dummy department
    dept = Department(name="NormalRoleDept", created_at=datetime.now(timezone.utc), created_by=3)
    session.add(dept)
    session.commit()
    session.refresh(dept)

    # -----------------------------
    # STEP 5: Attempt delete → should fail
    # -----------------------------
    resp = client.delete(f"/api/departments/{dept.id}", headers=headers)
    assert resp.status_code in (403, 404)
    print("User with normal role cannot delete department → PASSED")