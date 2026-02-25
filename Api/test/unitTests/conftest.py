import pytest
from sqlmodel import Session, SQLModel, create_engine, select
from sqlmodel.pool import StaticPool
from fastapi.testclient import TestClient
from src.main import app
from src.core.deps import get_db
from src.models.User import User, FixtureLoginResponse
from src.models.Role import Role, RoleType
from src.models.ClearanceToken import ClearanceTokens
from src.models.RoleToken import RoleToken, RoleTokenResponse
from src.models.Clearance import Clearance
from src.core.security import hash_password, create_access_token
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa 
from cryptography.hazmat.primitives import serialization 
from src.core.settings import settings
import jwt
from src.core.security import ALGORITHM
from src.models.Department import Department

@pytest.fixture(scope="session", autouse=True)
def setup_keys():
    # Generate global keys for tests
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    settings.PRIVATE_KEY = private_pem.decode()
    settings.PUBLIC_KEY = public_pem.decode()
    
@pytest.fixture(name="session")
def session_fixture():
    engine = create_engine(
        "sqlite://", 
        connect_args={"check_same_thread": False}, 
        poolclass=StaticPool
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        # Create all clearances
        for clearance_name in ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP_SECRET"]:
            existing = session.exec(
                select(Clearance).where(Clearance.name == clearance_name)
            ).first()
            if not existing:
                session.add(Clearance(name=clearance_name))
        
        # Create all roles
        for role_name in ["ADMINISTRATOR", "SECURITY_OFFICER", "TRUSTED_OFFICER", "STANDARD_USER", "AUDITOR"]:
            existing = session.exec(
                select(Role).where(Role.role == role_name)
            ).first()
            if not existing:
                session.add(Role(role=role_name))
        
        session.commit()
        
        yield session

@pytest.fixture(name="client")
def client_fixture(session: Session):
    def get_db_override():
        yield session

    app.dependency_overrides[get_db] = get_db_override
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


def create_user_with_role(session: Session, role_type: RoleType, user_name: str, clearance_name: str = "SECRET") -> FixtureLoginResponse:
    # 1. Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # 2. Get or Create Role
    role = session.exec(select(Role).where(Role.role == role_type)).first()
    if not role:
        # Create all roles if they don't exist
        for r_name in ["ADMINISTRATOR", "SECURITY_OFFICER", "TRUSTED_OFFICER", "STANDARD_USER", "AUDITOR"]:
            if not session.exec(select(Role).where(Role.role == r_name)).first():
                session.add(Role(role=r_name))
        session.commit()
        role = session.exec(select(Role).where(Role.role == role_type)).first()

    # 3. Create User
    hashed_password, salt = hash_password("password")
    user = User(
        user_name=user_name,
        hash_password=hashed_password,
        salt=salt,
        is_activated=True,
        assymetric_public_key=public_pem.decode()
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    # 4. Create Role Token
    issued_at = datetime.now(timezone.utc)
    expired_at = datetime.now(timezone.utc) + timedelta(days=365)
    
    role_token_payload = {
        "sub": str(user.id),
        "role_id": role.id,
        "dept_id": None,
        "iss": str(user.id), # Self-issued for fixture simplicity
        "iat": issued_at,
        "exp": expired_at
    }
    
    role_token_jwt = jwt.encode(role_token_payload, private_pem, algorithm=ALGORITHM)

    role_token = RoleToken(
        user_id=user.id,
        role_id=role.id,
        issued_by=user.id,
        issued_at=issued_at,
        signature=role_token_jwt
    )
    session.add(role_token)
    session.commit()
    session.refresh(role_token)

    # 5. Create Clearance Token
    clearance = session.exec(select(Clearance).where(Clearance.name == clearance_name)).first()
    if clearance:
        clearance_token = ClearanceTokens(
            user_id=user.id,
            clearance_id=clearance.id,
            issued_at=datetime.now(timezone.utc),
            expired_at=datetime.now(timezone.utc) + timedelta(days=1),
            issued_by=user.id,
            signature="fixture_clearance_sig"
        )
        session.add(clearance_token)
        session.commit()

    # 6. Create Access Token
    token = create_access_token(data={"sub": user.user_name, "id": user.id})
    
    return FixtureLoginResponse(
        access_token=token,
        token_type="bearer",
        user_id=user.id,
        role_tokens={role.role: RoleTokenResponse.model_validate(role_token)},
        private_key=private_pem.decode()
    )

@pytest.fixture(name="admin_keys")
def admin_keys_fixture():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return pem_private.decode(), pem_public.decode()

@pytest.fixture(name="admin_token")
def admin_token_fixture(session: Session):
    return create_user_with_role(session, "ADMINISTRATOR", "admin_fixture")

@pytest.fixture(name="security_officer_token")
def security_officer_token_fixture(session: Session):
    return create_user_with_role(session, "SECURITY_OFFICER", "sec_officer_fixture")

@pytest.fixture(name="trusted_officer_token")
def trusted_officer_token_fixture(session: Session):
    return create_user_with_role(session, "TRUSTED_OFFICER", "trusted_officer_fixture")

@pytest.fixture(name="standard_user_token")
def standard_user_token_fixture(session: Session):
    return create_user_with_role(session, "STANDARD_USER", "auth_user_fixture", clearance_name="UNCLASSIFIED")

@pytest.fixture(name="auditor_token")
def auditor_token_fixture(session: Session):
    return create_user_with_role(session, "AUDITOR", "auditor_fixture")

@pytest.fixture(name="clearance_token")
def clearance_token_fixture(client: TestClient, session: Session, security_officer_token: FixtureLoginResponse, standard_user_token: FixtureLoginResponse):
    
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
        "clearance_id": clearance.id,
        "dept_ids": [department.id],
        "iss": str(security_officer_token.user_id),
        "iat": issued_at,
        "exp": expired_at
    }
    
    clearance_jwt = jwt.encode(clearance_payload, security_officer_token.private_key, algorithm=ALGORITHM)
    
    payload = {
        "token": clearance_jwt
    }
    
    client.put(f"/api/users/{standard_user_token.user_id}/clearance", json=payload, headers=headers)

    return clearance_jwt, standard_user_token