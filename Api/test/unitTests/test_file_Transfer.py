import pytest
import jwt
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from src.main import app
from src.models.User import User, LoginResponse
from src.models.ClearanceDepartment import ClearanceDepartment
from src.models.Clearance import Clearance
from src.models.Department import Department
from src.models.ClearanceToken import ClearanceTokens
from src.models.Role import Role
from src.models.RoleToken import RoleToken
from src.core.security import hash_password, create_access_token
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os


# Helper function to create RoleToken for a user
def create_role_token_for_user(session: Session, user_id: int, role_name: str = "STANDARD_USER", department_id: int = None):
    role = session.exec(select(Role).where(Role.role == role_name)).first()
    if not role:
        role = Role(role=role_name)
        session.add(role)
        session.commit()
        session.refresh(role)
    
    role_token = RoleToken(
        user_id=user_id,
        role_id=role.id,
        department_id=department_id,
        issued_at=datetime.now(timezone.utc),
        issued_by=user_id,
        signature=f"sig_{user_id}_{role_name}"
    )
    session.add(role_token)
    session.commit()
    return role_token


def create_clearance_jwt(user_id: int, clearance_id: int, private_key):
    payload = {
        "iss": str(user_id),
        "sub": str(user_id),
        "clearance_id": clearance_id,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(days=1)
    }
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return jwt.encode(payload, private_key_pem, algorithm="RS256")


# =========================================================================================
# ORIGINAL TEST — MUST FAIL (NO CLEARANCE TOKEN)
# =========================================================================================

def test_upload_failed(client: TestClient, admin_token):
    # Admin logs in
    response = client.post(
        "/api/auth/login",
        json={"user_name": "admin_fixture", "password": "password"}
    )
    assert response.status_code == 200
    data = response.json()
    id = data["user_id"]
    token = data["access_token"]
    role_token_sig = data["role_tokens"]["ADMINISTRATOR"]["signature"]

    # Get admin public key
    user_info = client.get(f"/api/users/{id}/key",
                           headers={"Authorization": f"Bearer {token}"}).json()

    public_key = serialization.load_pem_public_key(
        user_info["assymetric_public_key"].encode()
    )

    # Create test file
    file_path = Path("/tmp/test_upload_file.txt")
    file_path.write_text("This is a test file for SecureShare upload!")

    file_data = file_path.read_bytes()

    # Encrypt with AES
    aes_key = os.urandom(32)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    enc = cipher.encryptor()
    encrypted_data = enc.update(file_data) + enc.finalize()
    tag = enc.tag

    # Encrypt AES key with admin’s public key
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

    files = {
        "file": (file_path.name, encrypted_data, "application/octet-stream")
    }
    data_payload = {
        "clearance_level": "UNCLASSIFIED",
        "is_private": "true",
        "department_list": "",
        "aes_iv": base64.b64encode(iv).decode(),
        "aes_tag": base64.b64encode(tag).decode(),
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode()
    }

    # Admin has SECRET, but request is UNCLASSIFIED → still allowed
    # But THIS test expects failure (keep as you said)
    upload_response = client.post(
        "api/transfers/",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Role-Token": role_token_sig
        },
        files=files,
        data=data_payload
    )

    print("\nUpload failed response:", upload_response.json())

    assert upload_response.status_code == 400



# =========================================================================================
# TEST — USER WITH A VALID CLEARANCE TOKEN CAN UPLOAD (SUCCESS)
# =========================================================================================

def test_upload_success(client: TestClient, session: Session):
    # Create RSA keypair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Create user
    hashed, salt = hash_password("1234")
    user = User(
        user_name="writer_user",
        hash_password=hashed,
        salt=salt,
        assymetric_public_key=public_key_pem.decode(),
        is_activated=True
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    # Give the user UNCLASSIFIED clearance via ClearanceTokens
    clearance = session.exec(
        select(Clearance).where(Clearance.name == "UNCLASSIFIED")
    ).first()

    # Create JWT for clearance token
    clearance_jwt = create_clearance_jwt(user.id, clearance.id, private_key)

    token = ClearanceTokens(
        user_id=user.id,
        clearance_id=clearance.id,
        issued_at=datetime.now(timezone.utc),
        expired_at=datetime.now(timezone.utc) + timedelta(days=1),
        issued_by=user.id,
        signature=clearance_jwt
    )
    session.add(token)
    session.commit()

    # Give the user STANDARD_USER role token
    create_role_token_for_user(session, user.id, "STANDARD_USER")

    # Create JWT
    jwt = create_access_token({"sub": user.user_name, "id": user.id})

    # Encrypt file using user's public key
    public_key = serialization.load_pem_public_key(public_key_pem)

    p = Path("/tmp/upload_success.txt")
    p.write_text("Upload OK")

    data_bytes = p.read_bytes()

    aes = os.urandom(32)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(aes), modes.GCM(iv))
    e = cipher.encryptor()
    encrypted = e.update(data_bytes) + e.finalize()
    tag = e.tag

    encrypted_key = public_key.encrypt(
        aes,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

    files = {
        "file": (p.name, encrypted, "application/octet-stream")
    }
    data = {
        "clearance_level": "UNCLASSIFIED",
        "is_private": "false",
        "department_list": "",
        "aes_iv": base64.b64encode(iv).decode(),
        "aes_tag": base64.b64encode(tag).decode(),
        "encrypted_aes_key": base64.b64encode(encrypted_key).decode()
    }

    resp = client.post("/api/transfers/",
                       headers={"Authorization": f"Bearer {jwt}", "X-Clearance-Token": clearance_jwt},
                       files=files,
                       data=data)

    print("\nUpload success response:", resp.json())

    assert resp.status_code == 200
    assert "uid" in resp.json()
    assert "file_name" in resp.json()



# =========================================================================================
# TEST — BELL-LAPADULA: TOP_SECRET USER CANNOT UPLOAD UNCLASSIFIED FILE (WRITE-DOWN BLOCKED)
# =========================================================================================

def test_bell_lapadula_no_write_down(client: TestClient, session: Session):
    """
    Bell-LaPadula:
        A user with TOP_SECRET clearance CANNOT write to an UNCLASSIFIED object.
        upload should return 403 Forbidden.
    """

    # -------------------------------------------------------------
    # 1) Generate RSA keypair for this user
    # -------------------------------------------------------------
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # -------------------------------------------------------------
    # 2) Create user
    # -------------------------------------------------------------
    hashed, salt = hash_password("write_down_pw")
    user = User(
        user_name="top_secret_user",
        hash_password=hashed,
        salt=salt,
        assymetric_public_key=public_key_pem.decode(),
        is_activated=True
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    # -------------------------------------------------------------
    # 3) Give the user TOP_SECRET clearance via ClearanceTokens
    # -------------------------------------------------------------
    top_clearance = session.exec(
        select(Clearance).where(Clearance.name == "TOP_SECRET")
    ).first()

    assert top_clearance is not None

    ts_jwt = create_clearance_jwt(user.id, top_clearance.id, private_key)

    ts_token = ClearanceTokens(
        user_id=user.id,
        clearance_id=top_clearance.id,
        issued_at=datetime.now(timezone.utc),
        expired_at=datetime.now(timezone.utc) + timedelta(days=1),
        issued_by=user.id,
        signature=ts_jwt
    )
    session.add(ts_token)
    session.commit()

    # Give the user STANDARD_USER role token
    create_role_token_for_user(session, user.id, "STANDARD_USER")

    # -------------------------------------------------------------
    # 4) Create JWT
    # -------------------------------------------------------------
    jwt = create_access_token({"sub": user.user_name, "id": user.id})

    # -------------------------------------------------------------
    # 5) Prepare encrypted file content
    # -------------------------------------------------------------
    p = Path("/tmp/blp_test.txt")
    p.write_text("TOP SECRET user attempting WRITE-DOWN — should fail.")

    plain_bytes = p.read_bytes()

    aes_key = os.urandom(32)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    enc = cipher.encryptor()
    encrypted_bytes = enc.update(plain_bytes) + enc.finalize()
    tag = enc.tag

    # Encrypt AES key with user's public key
    public_key = serialization.load_pem_public_key(public_key_pem)

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    files = {
        "file": (p.name, encrypted_bytes, "application/octet-stream")
    }

    # The user tries to upload the file as UNCLASSIFIED → ILLEGAL WRITE-DOWN
    data = {
        "clearance_level": "UNCLASSIFIED",    # ⛔ LOWER than user's TS clearance
        "is_private": "false",
        "department_list": "",
        "aes_iv": base64.b64encode(iv).decode(),
        "aes_tag": base64.b64encode(tag).decode(),
        "encrypted_aes_key": base64.b64encode(encrypted_key).decode()
    }

    # -------------------------------------------------------------
    # 6) Perform the upload — system must forbid write-down
    # -------------------------------------------------------------
    resp = client.post(
        "/api/transfers/",
        headers={"Authorization": f"Bearer {jwt}", "X-Clearance-Token": ts_jwt},
        files=files,
        data=data
    )

    print("\nBell-LaPadula response:", resp.json())

    # -------------------------------------------------------------
    # 7) Bell-LaPadula EXPECTED RESULT
    # -------------------------------------------------------------
    assert resp.status_code == 400


def test_upload_and_list_success(client: TestClient, session: Session):

    # -----------------------------
    # 1) Create user with UNCLASSIFIED clearance
    # -----------------------------
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    hashed, salt = hash_password("writer123")
    user = User(
        user_name="writer_user2",
        hash_password=hashed,
        salt=salt,
        assymetric_public_key=public_key_pem.decode(),
        is_activated=True
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    clearance = session.exec(select(Clearance).where(Clearance.name == "UNCLASSIFIED")).first()
    assert clearance is not None

    clearance_jwt = create_clearance_jwt(user.id, clearance.id, private_key)

    clearance_token = ClearanceTokens(
        user_id=user.id,
        clearance_id=clearance.id,
        issued_at=datetime.now(timezone.utc),
        expired_at=datetime.now(timezone.utc) + timedelta(days=1),
        issued_by=user.id,
        signature=clearance_jwt
    )
    session.add(clearance_token)
    session.commit()

    # Give the user STANDARD_USER role token
    create_role_token_for_user(session, user.id, "STANDARD_USER")

    # -----------------------------
    # 2) Generate JWT for the user
    # -----------------------------
    token = create_access_token({"sub": user.user_name, "id": user.id})

    # -----------------------------
    # 3) Encrypt file with user's public key
    # -----------------------------
    file_path = Path("/tmp/test_file_success.txt")
    file_path.write_text("This is a valid upload test!")

    file_data = file_path.read_bytes()
    aes_key = os.urandom(32)
    iv = os.urandom(12)

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(file_data) + encryptor.finalize()
    tag = encryptor.tag

    public_key = serialization.load_pem_public_key(public_key_pem)
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    files = {"file": (file_path.name, encrypted_data, "application/octet-stream")}
    data = {
        "clearance_level": "UNCLASSIFIED",
        "is_private": "false",
        "department_list": "",
        "aes_iv": base64.b64encode(iv).decode(),
        "aes_tag": base64.b64encode(tag).decode(),
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode()
    }

    # -----------------------------
    # 4) Upload file
    # -----------------------------
    resp = client.post(
        "/api/transfers/",
        headers={"Authorization": f"Bearer {token}", "X-Clearance-Token": clearance_jwt},
        files=files,
        data=data
    )

    assert resp.status_code == 200
    uploaded_file = resp.json()
    assert "uid" in uploaded_file
    assert uploaded_file["file_name"] == file_path.name

    # -----------------------------
    # 5) List files and verify
    # -----------------------------
    list_resp = client.get(
        "/api/transfers/",
        headers={"Authorization": f"Bearer {token}", "X-Clearance-Token": clearance_jwt}
    )
    assert list_resp.status_code == 200
    files_list = list_resp.json()
    assert any(f["uid"] == uploaded_file["uid"] for f in files_list)

    # Cleanup
    file_path.unlink(missing_ok=True)


# =========================================================================================
# TEST — SHARE A FILE WITH A USER THAT DOESNT HAVE PERMISSION TO READ IT
# =========================================================================================

def test_file_upload_and_share_fail(client: TestClient, session: Session):
    # fails because the user trying toa acess doesnt have enought clearance to read it

    # -----------------------------
    # 1) Create admin user with SECRET clearance
    # -----------------------------
    admin_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    admin_pub_pem = admin_priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    hashed_admin, salt_admin = hash_password("adminpw")
    admin = User(user_name="admin", hash_password=hashed_admin, salt=salt_admin,
                 assymetric_public_key=admin_pub_pem.decode(), is_activated=True)
    session.add(admin)
    session.commit()
    session.refresh(admin)


    clearance_secret = session.exec(select(Clearance).where(Clearance.name=="SECRET")).first()
    signature = create_clearance_jwt(admin.id, clearance_secret.id, admin_priv)

    admin_token_obj = ClearanceTokens(
        user_id=admin.id,
        clearance_id=clearance_secret.id,
        issued_at=datetime.now(timezone.utc),
        expired_at=datetime.now(timezone.utc)+timedelta(days=1),
        issued_by=admin.id,
        signature=signature
    )
    session.add(admin_token_obj)
    session.commit()
    
    # Give admin STANDARD_USER role token
    create_role_token_for_user(session, admin.id, "STANDARD_USER")
    
    admin_jwt = create_access_token({"sub": admin.user_name, "id": admin.id})

    # -----------------------------
    # 2) Create user1 with UNCLASSIFIED clearance
    # -----------------------------
    user1_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    user1_pub_pem = user1_priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    hashed_u1, salt_u1 = hash_password("user1pw")
    user1 = User(user_name="user1", hash_password=hashed_u1, salt=salt_u1,
                 assymetric_public_key=user1_pub_pem.decode(), is_activated=True)
    session.add(user1)
    session.commit()
    session.refresh(user1)

    clearance_unclassified = session.exec(select(Clearance).where(Clearance.name=="UNCLASSIFIED")).first()
    user1_jwt_token = create_clearance_jwt(user1.id, clearance_unclassified.id, user1_priv)

    token_user1 = ClearanceTokens(
        user_id=user1.id,
        clearance_id=clearance_unclassified.id,
        issued_at=datetime.now(timezone.utc),
        expired_at=datetime.now(timezone.utc)+timedelta(days=1),
        issued_by=admin.id,
        signature=user1_jwt_token
    )
    session.add(token_user1)
    session.commit()
    user1_jwt = create_access_token({"sub": user1.user_name, "id": user1.id})

    # -----------------------------
    # 3) Admin uploads a file
    # -----------------------------
    file_path = Path("/tmp/shared_file.txt")
    file_path.write_text("Secret file for sharing")
    file_bytes = file_path.read_bytes()

    aes_key = os.urandom(32)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    enc = cipher.encryptor()
    encrypted_data = enc.update(file_bytes) + enc.finalize()
    tag = enc.tag

    encrypted_aes_key_admin = admin_priv.public_key().encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    files = {"file": (file_path.name, encrypted_data, "application/octet-stream")}
    data = {
        "clearance_level": "SECRET",
        "is_private": "true",
        "department_list": "",
        "aes_iv": base64.b64encode(iv).decode(),
        "aes_tag": base64.b64encode(tag).decode(),
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key_admin).decode()
    }

    upload_resp = client.post("/api/transfers/", headers={"Authorization": f"Bearer {admin_jwt}", "X-Clearance-Token": admin_token_obj.signature},
                              files=files, data=data)
    assert upload_resp.status_code == 200
    uploaded_file_uid = upload_resp.json()["uid"]

    # -----------------------------
    # 4) Share file with user1
    # -----------------------------
    # Decrypt AES key (simulate what admin does)
    decrypted_aes = admin_priv.decrypt(
        base64.b64decode(upload_resp.json()["symetric_key_encrypted"]),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # Encrypt AES key with user1's public key
    user1_pub_key = serialization.load_pem_public_key(user1_pub_pem)
    encrypted_aes_for_user1 = user1_pub_key.encrypt(
        decrypted_aes,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    share_resp = client.post("/api/transfers/share/", headers={"Authorization": f"Bearer {admin_jwt}", "X-Clearance-Token": admin_token_obj.signature},
                             data={
                                 "file_uid": uploaded_file_uid,
                                 "user_share_id": user1.id,
                                 "encrypted_aes_key": base64.b64encode(encrypted_aes_for_user1).decode()
                             })
    assert share_resp.status_code == 200

    # -----------------------------
    # 6) user1 downloads the file
    # -----------------------------

    # seing that the user is only unclassified permission it can dowload it 
    download_resp = client.get(f"/api/download/{uploaded_file_uid}", headers={"Authorization": f"Bearer {user1_jwt}", "X-Clearance-Token": user1_jwt_token})
    assert download_resp.status_code == 404


    file_path.unlink(missing_ok=True)

# =========================================================================================
# TEST — SHARE A FILE WITH A USER THAT HAS PERMISSION TO READ IT
# =========================================================================================

def test_file_upload_and_share(client: TestClient, session: Session):

    # -----------------------------
    # 1) Create admin user with SECRET clearance
    # -----------------------------
    admin_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    admin_pub_pem = admin_priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    hashed_admin, salt_admin = hash_password("adminpw")
    admin = User(user_name="admin", hash_password=hashed_admin, salt=salt_admin,
                 assymetric_public_key=admin_pub_pem.decode(), is_activated=True)
    session.add(admin)
    session.commit()
    session.refresh(admin)

    clearance_secret = session.exec(select(Clearance).where(Clearance.name=="SECRET")).first()

    signature = create_clearance_jwt(admin.id, clearance_secret.id, admin_priv)

    admin_token_obj = ClearanceTokens(
        user_id=admin.id,
        clearance_id=clearance_secret.id,
        issued_at=datetime.now(timezone.utc),
        expired_at=datetime.now(timezone.utc)+timedelta(days=1),
        issued_by=admin.id,
        signature=signature
    )
    session.add(admin_token_obj)
    session.commit()
    
    # Give admin STANDARD_USER role token
    create_role_token_for_user(session, admin.id, "STANDARD_USER")
    
    admin_jwt = create_access_token({"sub": admin.user_name, "id": admin.id})

    # -----------------------------
    # 2) Create user1 with UNCLASSIFIED clearance
    # -----------------------------
    user1_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    user1_pub_pem = user1_priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    hashed_u1, salt_u1 = hash_password("user1pw")
    user1 = User(user_name="user1", hash_password=hashed_u1, salt=salt_u1,
                 assymetric_public_key=user1_pub_pem.decode(), is_activated=True)
    session.add(user1)
    session.commit()
    session.refresh(user1)

    user1_jwt_token = create_clearance_jwt(user1.id, clearance_secret.id, user1_priv)

    token_user1 = ClearanceTokens(
        user_id=user1.id,
        clearance_id=clearance_secret.id,
        issued_at=datetime.now(timezone.utc),
        expired_at=datetime.now(timezone.utc)+timedelta(days=1),
        issued_by=admin.id,
        signature=user1_jwt_token
    )
    session.add(token_user1)
    session.commit()
    user1_jwt = create_access_token({"sub": user1.user_name, "id": user1.id})

    # -----------------------------
    # 3) Admin uploads a file
    # -----------------------------
    file_path = Path("/tmp/shared_file.txt")
    file_path.write_text("Secret file for sharing")
    file_bytes = file_path.read_bytes()

    aes_key = os.urandom(32)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    enc = cipher.encryptor()
    encrypted_data = enc.update(file_bytes) + enc.finalize()
    tag = enc.tag

    encrypted_aes_key_admin = admin_priv.public_key().encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    files = {"file": (file_path.name, encrypted_data, "application/octet-stream")}
    data = {
        "clearance_level": "SECRET",
        "is_private": "true",
        "department_list": "",
        "aes_iv": base64.b64encode(iv).decode(),
        "aes_tag": base64.b64encode(tag).decode(),
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key_admin).decode()
    }

    upload_resp = client.post("/api/transfers/", headers={"Authorization": f"Bearer {admin_jwt}", "X-Clearance-Token": admin_token_obj.signature},
                              files=files, data=data)
    assert upload_resp.status_code == 200
    uploaded_file_uid = upload_resp.json()["uid"]

    # -----------------------------
    # 4) Share file with user1
    # -----------------------------
    # Decrypt AES key (simulate what admin does)
    decrypted_aes = admin_priv.decrypt(
        base64.b64decode(upload_resp.json()["symetric_key_encrypted"]),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # Encrypt AES key with user1's public key
    user1_pub_key = serialization.load_pem_public_key(user1_pub_pem)
    encrypted_aes_for_user1 = user1_pub_key.encrypt(
        decrypted_aes,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    share_resp = client.post("/api/transfers/share/", headers={"Authorization": f"Bearer {admin_jwt}", "X-Clearance-Token": admin_token_obj.signature},
                             data={
                                 "file_uid": uploaded_file_uid,
                                 "user_share_id": user1.id,
                                 "encrypted_aes_key": base64.b64encode(encrypted_aes_for_user1).decode()
                             })
    assert share_resp.status_code == 200

    # -----------------------------
    # 5) user1 lists files and verifies shared file appears
    # -----------------------------
    list_resp = client.get("/api/transfers/", headers={"Authorization": f"Bearer {user1_jwt}", "X-Clearance-Token": user1_jwt_token})
    assert list_resp.status_code == 200
    files_list = list_resp.json()
    # Verify the shared file appears in user1's file list
    shared_file_uids = [f["uid"] for f in files_list]
    assert uploaded_file_uid in shared_file_uids, f"Shared file {uploaded_file_uid} not found in user1's file list: {shared_file_uids}"

    # -----------------------------
    # 6) user1 downloads the file
    # -----------------------------
    download_resp = client.get(f"/api/download/{uploaded_file_uid}", headers={"Authorization": f"Bearer {user1_jwt}", "X-Clearance-Token": user1_jwt_token})
    assert download_resp.status_code == 200
    assert download_resp.content != b""

    file_path.unlink(missing_ok=True)

def test_public_file_access_with_higher_clearance_same_department(client: TestClient, session: Session):
    """
    PUBLIC file:
        - Still requires department permission
        - Still requires clearance >= file
        - Only bypasses explicit 'share'
    User A uploads the file (UNCLASSIFIED)
    User B has TOP_SECRET clearance + same department → must access successfully.
    """

    # -----------------------------
    # 1) Create department
    # -----------------------------
    dept = Department(
        name="PublicDept",
        created_at=datetime.now(),
        created_by=1,
        hierarchy_level=1
    )
    session.add(dept)
    session.commit()
    session.refresh(dept)

    # ============================================================
    # 2) USER A (Uploader) — UNCLASSIFIED
    # ============================================================
    privA = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pubA_pem = privA.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    hashedA, saltA = hash_password("passA")
    userA = User(
        user_name="uploader_user",
        hash_password=hashedA,
        salt=saltA,
        assymetric_public_key=pubA_pem,
        is_activated=True
    )
    session.add(userA)
    session.commit()
    session.refresh(userA)

    # Clearance UNCLASSIFIED for A
    clearance_unclassified = session.exec(
        select(Clearance).where(Clearance.name == "UNCLASSIFIED")
    ).first()

    jwtA = create_clearance_jwt(userA.id, clearance_unclassified.id, privA)

    tokenA_cl = ClearanceTokens(
        user_id=userA.id,
        clearance_id=clearance_unclassified.id,
        issued_at=datetime.now(),
        expired_at=datetime.now() + timedelta(days=1),
        issued_by=userA.id,
        signature=jwtA
    )
    session.add(tokenA_cl)
    session.commit()

    # Give user A STANDARD_USER role token with department
    create_role_token_for_user(session, userA.id, "STANDARD_USER", dept.id)

    # Add department membership
    deptA = ClearanceDepartment(
        clearance_token_id=tokenA_cl.id,
        department_id=dept.id,
    )
    session.add(deptA)
    session.commit()

    # ============================================================
    # 3) USER B (Downloader) — HIGHER CLEARANCE (TOP_SECRET)
    # ============================================================
    privB = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pubB_pem = privB.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    hashedB, saltB = hash_password("passB")
    userB = User(
        user_name="reader_user_high",
        hash_password=hashedB,
        salt=saltB,
        assymetric_public_key=pubB_pem,
        is_activated=True
    )
    session.add(userB)
    session.commit()
    session.refresh(userB)

    # Clearance TOP SECRET for B
    clearance_TS = session.exec(
        select(Clearance).where(Clearance.name == "TOP_SECRET")
    ).first()

    jwtB = create_clearance_jwt(userB.id, clearance_TS.id, privB)

    tokenB_cl = ClearanceTokens(
        user_id=userB.id,
        clearance_id=clearance_TS.id,
        issued_at=datetime.now(),
        expired_at=datetime.now() + timedelta(days=1),
        issued_by=userB.id,
        signature=jwtB
    )
    session.add(tokenB_cl)
    session.commit()

    # User B is in the SAME department
    deptB = ClearanceDepartment(
        clearance_token_id=tokenB_cl.id,
        department_id=dept.id,
    )
    session.add(deptB)
    session.commit()

    # ============================================================
    # 4) USER A uploads a PUBLIC file (UNCLASSIFIED)
    # ============================================================
    tokenA = create_access_token({"sub": userA.user_name, "id": userA.id})

    file_path = Path("/tmp/public_dep_file.txt")
    file_path.write_text("Department-protected public file")

    file_bytes = file_path.read_bytes()
    aes_key = os.urandom(32)
    iv = os.urandom(12)

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(file_bytes) + encryptor.finalize()
    tag = encryptor.tag

    # Encrypt AES key using USER A's public key
    publicA = serialization.load_pem_public_key(pubA_pem.encode())
    encrypted_aes_key = publicA.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    files = {"file": (file_path.name, encrypted_data, "application/octet-stream")}
    data_upload = {
        "clearance_level": "UNCLASSIFIED",
        "is_private": "false",             # <-- PUBLIC but NOT open
        "department_list": str(dept.id),   # <-- Still protected by department
        "aes_iv": base64.b64encode(iv).decode(),
        "aes_tag": base64.b64encode(tag).decode(),
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),
    }

    upload_resp = client.post(
        "/api/transfers/",
        headers={"Authorization": f"Bearer {tokenA}", "X-Clearance-Token": jwtA},
        files=files,
        data=data_upload
    )
    assert upload_resp.status_code == 200
    file_uid = upload_resp.json()["uid"]

    # ============================================================
    # 5) USER B logs in and downloads successfully
    # ============================================================
    tokenB = create_access_token({"sub": userB.user_name, "id": userB.id})
    headersB = {"Authorization": f"Bearer {tokenB}", "X-Clearance-Token": jwtB}

    download_resp = client.get(f"/api/download/{file_uid}", headers=headersB)
    assert download_resp.status_code == 200

    # Decrypt using the original AES key
    iv_dl = base64.b64decode(download_resp.headers.get("X-IV"))
    tag_dl = base64.b64decode(download_resp.headers.get("X-Tag"))
    decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv_dl, tag_dl)).decryptor()
    plaintext = decryptor.update(download_resp.content) + decryptor.finalize()

    assert plaintext == b"Department-protected public file"

    file_path.unlink(missing_ok=True)



def test_upload_and_download_with_permission(client: TestClient, session: Session):
    # -----------------------------
    # 1) Create user
    # -----------------------------
    priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = priv_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    hashed, salt = hash_password("password")
    user = User(user_name="user_with_access", hash_password=hashed, salt=salt,
                assymetric_public_key=pub_pem.decode(), is_activated=True)
    session.add(user)
    session.commit()
    session.refresh(user)

    # 2) Create department
    # -----------------------------
    # -----------------------------
    dept = Department(name="R&D",created_at=datetime.now(),created_by=user.id)
    session.add(dept)
    session.commit()
    session.refresh(dept)

    # -----------------------------
    # 3) Clearance
    # -----------------------------
    clearance = session.exec(select(Clearance).where(Clearance.name=="UNCLASSIFIED")).first()

    jwt_token = create_clearance_jwt(user.id, clearance.id, priv_key)

    token = ClearanceTokens(
        user_id=user.id,
        clearance_id=clearance.id,
        issued_at=None,
         expired_at=datetime.now()+timedelta(days=3),
        issued_by=user.id,
        signature=jwt_token
    )
    session.add(token)
    session.commit()
    session.refresh(token)

    # Give the user STANDARD_USER role token with department
    create_role_token_for_user(session, user.id, "STANDARD_USER", dept.id)

    clearance_dep =ClearanceDepartment(clearance_token_id=token.id,department_id=dept.id)
    session.add(clearance_dep)
    session.commit()
    session.refresh(clearance_dep)
    # -----------------------------
    # 4) Upload file
    # -----------------------------
    file_path = Path("/tmp/department_file.txt")
    file_path.write_text("Department restricted file")
    file_bytes = file_path.read_bytes()

    aes_key = os.urandom(32)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(file_bytes) + encryptor.finalize()
    tag = encryptor.tag

    public_key = serialization.load_pem_public_key(pub_pem)
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    files = {"file": (file_path.name, encrypted_data, "application/octet-stream")}
    data_payload = {
        "clearance_level": "UNCLASSIFIED",
        "is_private": "true",
        "department_list": str(dept.id),
        "aes_iv": base64.b64encode(iv).decode(),
        "aes_tag": base64.b64encode(tag).decode(),
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode()
    }

    jwt = create_access_token({"sub": user.user_name, "id": user.id})
    upload_resp = client.post("/api/transfers/", headers={"Authorization": f"Bearer {jwt}", "X-Clearance-Token": jwt_token},
                              files=files, data=data_payload)
    assert upload_resp.status_code == 200
    file_uid = upload_resp.json()["uid"]

    # -----------------------------
    # 5) Download as same user
    # -----------------------------
    download_resp = client.get(f"/api/download/{file_uid}", headers={"Authorization": f"Bearer {jwt}", "X-Clearance-Token": jwt_token})
    assert download_resp.status_code == 200

    enc_key = base64.b64decode(download_resp.headers.get("X-Encrypted-Key"))
    iv_bytes = base64.b64decode(download_resp.headers.get("X-IV"))
    tag_bytes = base64.b64decode(download_resp.headers.get("X-Tag"))

    aes_key_decrypted = priv_key.decrypt(
        enc_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    decryptor = Cipher(algorithms.AES(aes_key_decrypted), modes.GCM(iv_bytes, tag_bytes)).decryptor()
    plaintext = decryptor.update(download_resp.content) + decryptor.finalize()
    assert plaintext == b"Department restricted file"

    file_path.unlink(missing_ok=True)

# ------------------------------------------
# TEST 2: Download without permission
# ------------------------------------------
def test_download_without_permission(client: TestClient, session: Session):
    # -----------------------------
    # 1) Create users
    # -----------------------------
    priv_key1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem1 = priv_key1.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    hashed1, salt1 = hash_password("password")
    user_with_access = User(user_name="user_with_access", hash_password=hashed1, salt=salt1,
                            assymetric_public_key=pub_pem1.decode(), is_activated=True)
    session.add(user_with_access)
    session.commit()
    session.refresh(user_with_access)

    priv_key2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem2 = priv_key2.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    hashed2, salt2 = hash_password("password")
    user_no_access = User(user_name="user_no_access", hash_password=hashed2, salt=salt2,
                          assymetric_public_key=pub_pem2.decode(), is_activated=True)
    session.add(user_no_access)
    session.commit()
    session.refresh(user_no_access)

    # -----------------------------
    # 2) Department
    # -----------------------------
    dept = Department(name="R&D",created_at=datetime.now(),created_by=user_with_access.id)
    session.add(dept)
    session.commit()
    session.refresh(dept)

    # -----------------------------
    # 3) Clearance and token for user_with_access
    # -----------------------------
    clearance = session.exec(select(Clearance).where(Clearance.name=="UNCLASSIFIED")).first()
    jwt_token = create_clearance_jwt(user_with_access.id, clearance.id, priv_key1)

    token = ClearanceTokens(
        user_id=user_with_access.id,
        clearance_id=clearance.id,
        issued_at=None,
        expired_at= datetime.now()+timedelta(days=3),
        issued_by=user_with_access.id,
        signature=jwt_token
    )
    session.add(token)
    session.commit()
    session.refresh(token)

    # Give user_with_access STANDARD_USER role token with department
    create_role_token_for_user(session, user_with_access.id, "STANDARD_USER", dept.id)

    clearance_dep =ClearanceDepartment(clearance_token_id=token.id,department_id=dept.id)
    session.add(clearance_dep)
    session.commit()
    session.refresh(clearance_dep)

    # -----------------------------
    # 4) Upload file with user_with_access
    # -----------------------------
    file_path = Path("/tmp/department_file2.txt")
    file_path.write_text("Department restricted file")
    file_bytes = file_path.read_bytes()

    aes_key = os.urandom(32)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(file_bytes) + encryptor.finalize()
    tag = encryptor.tag

    public_key = serialization.load_pem_public_key(pub_pem1)
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    files = {"file": (file_path.name, encrypted_data, "application/octet-stream")}
    data_payload = {
        "clearance_level": "UNCLASSIFIED",
        "is_private": "true",
        "department_list": str(dept.id),
        "aes_iv": base64.b64encode(iv).decode(),
        "aes_tag": base64.b64encode(tag).decode(),
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode()
    }

    jwt_access = create_access_token({"sub": user_with_access.user_name, "id": user_with_access.id})
    upload_resp = client.post("/api/transfers/", headers={"Authorization": f"Bearer {jwt_access}", "X-Clearance-Token": jwt_token}, files=files, data=data_payload)
    assert upload_resp.status_code == 200
    file_uid = upload_resp.json()["uid"]

    # -----------------------------
    # 5) Attempt download with user_no_access → should fail
    # -----------------------------
    jwt_no_access = create_access_token({"sub": user_no_access.user_name, "id": user_no_access.id})
    download_resp = client.get(f"/api/download/{file_uid}", headers={"Authorization": f"Bearer {jwt_no_access}"})
    assert download_resp.status_code == 404

    file_path.unlink(missing_ok=True)

def test_public_file_access_fail_lower_or_no_clearance(client: TestClient, session: Session):
    """
    PUBLIC file still requires:
        - department permission
        - clearance >= file clearance
    User B:
        - Not enough clearance (or none)
        - Even if same department → must FAIL
    """

    # -----------------------------
    # 1) Create department
    # -----------------------------
    dept = Department(
        name="PublicDeptFail",
        created_at=datetime.now(),
        created_by=1,
        hierarchy_level=1
    )
    session.add(dept)
    session.commit()
    session.refresh(dept)

    # ============================================================
    # 2) USER A (Uploader) — UNCLASSIFIED
    # ============================================================
    privA = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pubA_pem = privA.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    hashedA, saltA = hash_password("passA")
    userA = User(
        user_name="uploader_user_fail",
        hash_password=hashedA,
        salt=saltA,
        assymetric_public_key=pubA_pem,
        is_activated=True
    )
    session.add(userA)
    session.commit()
    session.refresh(userA)

    # Clearance UNCLASSIFIED for A
    clearance_unclassified = session.exec(
        select(Clearance).where(Clearance.name == "UNCLASSIFIED")
    ).first()

    jwtA = create_clearance_jwt(userA.id, clearance_unclassified.id, privA)

    tokenA_cl = ClearanceTokens(
        user_id=userA.id,
        clearance_id=clearance_unclassified.id,
        issued_at=datetime.now(),
        expired_at=datetime.now() + timedelta(days=1),
        issued_by=userA.id,
        signature=jwtA
    )
    session.add(tokenA_cl)
    session.commit()

    # Give user A STANDARD_USER role token with department
    create_role_token_for_user(session, userA.id, "STANDARD_USER", dept.id)

    # Attach department
    deptA = ClearanceDepartment(
        clearance_token_id=tokenA_cl.id,
        department_id=dept.id,
    )
    session.add(deptA)
    session.commit()

    # ============================================================
    # 3) USER B (Downloader) — NO CLEARANCE TOKEN
    # ============================================================
    privB = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pubB_pem = privB.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    hashedB, saltB = hash_password("passB")
    userB = User(
        user_name="reader_no_clearance",
        hash_password=hashedB,
        salt=saltB,
        assymetric_public_key=pubB_pem,
        is_activated=True
    )
    session.add(userB)
    session.commit()
    session.refresh(userB)

    # User B is in SAME department but has ZERO clearance
    deptB = ClearanceDepartment(
        clearance_token_id=None,  
        department_id=dept.id
    )
    # But this is wrong because ClearanceDepartment requires a token.
    # So we do NOT add a department token for B.
    # They effectively have NO department privilege.

    # ============================================================
    # 4) USER A uploads a PUBLIC department-protected file
    # ============================================================
    tokenA = create_access_token({"sub": userA.user_name, "id": userA.id})

    file_path = Path("/tmp/public_dep_file_fail.txt")
    file_path.write_text("Department-protected public file should not be accessible")

    file_bytes = file_path.read_bytes()
    aes_key = os.urandom(32)
    iv = os.urandom(12)

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(file_bytes) + encryptor.finalize()
    tag = encryptor.tag

    publicA = serialization.load_pem_public_key(pubA_pem.encode())
    encrypted_aes_key = publicA.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    files = {"file": (file_path.name, encrypted_data, "application/octet-stream")}
    data_upload = {
        "clearance_level": "UNCLASSIFIED",
        "is_private": "false",
        "department_list": str(dept.id),
        "aes_iv": base64.b64encode(iv).decode(),
        "aes_tag": base64.b64encode(tag).decode(),
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode()
    }

    upload_resp = client.post(
        "/api/transfers/",
        headers={"Authorization": f"Bearer {tokenA}", "X-Clearance-Token": jwtA},
        files=files,
        data=data_upload
    )
    assert upload_resp.status_code == 200
    file_uid = upload_resp.json()["uid"]

    # ============================================================
    # 5) USER B tries to download → FAIL (no clearance)
    # ============================================================
    tokenB = create_access_token({"sub": userB.user_name, "id": userB.id})
    headersB = {"Authorization": f"Bearer {tokenB}"}

    resp = client.get(f"/api/download/{file_uid}", headers=headersB)

    # Your app usually sends 404 for "no permission"
    assert resp.status_code in (401, 403, 404)

    file_path.unlink(missing_ok=True)

def test_public_file_no_department_lower_clearance_fails(client: TestClient, session: Session):
    """
    PUBLIC file, no department assigned.
    Only requirement: user clearance >= file clearance.

    User A uploads (SECRET).
    User B has UNCLASSIFIED → must NOT be allowed.
    """

    # -----------------------------
    # 1) USER A — SECRET clearance
    # -----------------------------
    privA = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pubA_pem = privA.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    hashedA, saltA = hash_password("passA")
    userA = User(
        user_name="uploader_secret",
        hash_password=hashedA,
        salt=saltA,
        assymetric_public_key=pubA_pem,
        is_activated=True
    )
    session.add(userA)
    session.commit()
    session.refresh(userA)

    clearance_secret = session.exec(
        select(Clearance).where(Clearance.name == "SECRET")
    ).first()

    jwtB_cl = create_clearance_jwt(userA.id, clearance_secret.id, privA)

    tokenA = ClearanceTokens(
        user_id=userA.id,
        clearance_id=clearance_secret.id,
        issued_at=datetime.now(),
        expired_at=datetime.now() + timedelta(days=1),
        issued_by=userA.id,
        signature=jwtB_cl
    )
    session.add(tokenA)
    session.commit()

    # Give user A STANDARD_USER role token
    create_role_token_for_user(session, userA.id, "STANDARD_USER")

    jwtA = create_access_token({"sub": userA.user_name, "id": userA.id})

    # -----------------------------
    # 2) USER A uploads PUBLIC file (SECRET)
    # -----------------------------
    file_path = Path("/tmp/public_no_dept_secret.txt")
    file_path.write_text("secret public no department")

    file_bytes = file_path.read_bytes()
    aes_key = os.urandom(32)
    iv = os.urandom(12)

    encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv)).encryptor()
    encrypted_data = encryptor.update(file_bytes) + encryptor.finalize()
    tag = encryptor.tag

    publicA = serialization.load_pem_public_key(pubA_pem.encode())
    enc_key = publicA.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

    )

    upload_data = {
        "clearance_level": "SECRET",
        "is_private": "false",
        "department_list": "",     # <-- NO DEPARTMENT
        "aes_iv": base64.b64encode(iv).decode(),
        "aes_tag": base64.b64encode(tag).decode(),
        "encrypted_aes_key": base64.b64encode(enc_key).decode(),
    }

    files = {"file": (file_path.name, encrypted_data, "application/octet-stream")}

    upload_resp = client.post(
        "/api/transfers/",
        headers={"Authorization": f"Bearer {jwtA}", "X-Clearance-Token": jwtB_cl},
        files=files,
        data=upload_data
    )
    assert upload_resp.status_code == 200
    file_uid = upload_resp.json()["uid"]

    # -----------------------------
    # 3) USER B — UNCLASSIFIED clearance
    # -----------------------------
    privB = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pubB_pem = privB.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    hashedB, saltB = hash_password("passB")
    userB = User(
        user_name="low_clearance_user",
        hash_password=hashedB,
        salt=saltB,
        assymetric_public_key=pubB_pem,
        is_activated=True
    )
    session.add(userB)
    session.commit()
    session.refresh(userB)

    clearance_unclass = session.exec(
        select(Clearance).where(Clearance.name == "UNCLASSIFIED")
    ).first()

    jwtB_cl = create_clearance_jwt(userB.id, clearance_unclass.id, privB)

    tokenB = ClearanceTokens(
        user_id=userB.id,
        clearance_id=clearance_unclass.id,
        issued_at=datetime.now(),
        expired_at=datetime.now() + timedelta(days=1),
        issued_by=userB.id,
        signature=jwtB_cl
    )
    session.add(tokenB)
    session.commit()

    jwtB = create_access_token({"sub": userB.user_name, "id": userB.id})

    # -----------------------------
    # 4) User B tries to download → must FAIL
    # -----------------------------
    resp = client.get(f"/api/download/{file_uid}", headers={"Authorization": f"Bearer {jwtB}", "X-Clearance-Token": jwtB_cl})
    assert resp.status_code == 404

    file_path.unlink(missing_ok=True)

def test_public_file_no_department_higher_clearance_succeeds(client: TestClient, session: Session):
    """
    PUBLIC file, no department.
    Only requirement: clearance >= file.

    User A uploads (SECRET).
    User B has TOP_SECRET → MUST access.
    """

    # -----------------------------
    # 1) USER A — SECRET clearance
    # -----------------------------
    privA = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pubA_pem = privA.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    hashedA, saltA = hash_password("passA")
    userA = User(
        user_name="uploader_secret2",
        hash_password=hashedA,
        salt=saltA,
        assymetric_public_key=pubA_pem,
        is_activated=True
    )
    session.add(userA)
    session.commit()
    session.refresh(userA)

    clearance_secret = session.exec(
        select(Clearance).where(Clearance.name == "SECRET")
    ).first()

    # Create JWT for clearance token
    clearance_jwt = create_clearance_jwt(userA.id, clearance_secret.id, privA)

    tokenA = ClearanceTokens(
        user_id=userA.id,
        clearance_id=clearance_secret.id,
        issued_at=datetime.now(timezone.utc),
        expired_at=datetime.now(timezone.utc) + timedelta(days=1),
        issued_by=userA.id,
        signature=clearance_jwt
    )
    session.add(tokenA)
    session.commit()

    # Give user A STANDARD_USER role token
    create_role_token_for_user(session, userA.id, "STANDARD_USER")

    jwtA = create_access_token({"sub": userA.user_name, "id": userA.id})

    # -----------------------------
    # 2) Upload PUBLIC SECRET file (NO DEPARTMENT)
    # -----------------------------
    file_path = Path("/tmp/public_no_dept_secret2.txt")
    file_path.write_text("accessible secret public file")

    file_bytes = file_path.read_bytes()
    aes_key = os.urandom(32)
    iv = os.urandom(12)

    encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv)).encryptor()
    encrypted_data = encryptor.update(file_bytes) + encryptor.finalize()
    tag = encryptor.tag

    publicA = serialization.load_pem_public_key(pubA_pem.encode())
    enc_key = publicA.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

    )

    upload_data = {
        "clearance_level": "SECRET",
        "is_private": "false",
        "department_list": "",      # <-- NO DEPARTMENT
        "aes_iv": base64.b64encode(iv).decode(),
        "aes_tag": base64.b64encode(tag).decode(),
        "encrypted_aes_key": base64.b64encode(enc_key).decode(),
    }

    files = {"file": (file_path.name, encrypted_data, "application/octet-stream")}

    upload_resp = client.post(
        "/api/transfers/",
        headers={"Authorization": f"Bearer {jwtA}", "X-Clearance-Token": clearance_jwt},
        files=files,
        data=upload_data
    )
    assert upload_resp.status_code == 200
    file_uid = upload_resp.json()["uid"]

    # -----------------------------
    # 3) USER B with HIGHER clearance (TOP_SECRET)
    # -----------------------------
    privB = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pubB_pem = privB.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    hashedB, saltB = hash_password("passB")
    userB = User(
        user_name="high_clearance_user",
        hash_password=hashedB,
        salt=saltB,
        assymetric_public_key=pubB_pem,
        is_activated=True
    )
    session.add(userB)
    session.commit()
    session.refresh(userB)

    clearance_top = session.exec(
        select(Clearance).where(Clearance.name == "TOP_SECRET")
    ).first()

    jwtB_cl = create_clearance_jwt(userB.id, clearance_top.id, privB)

    tokenB = ClearanceTokens(
        user_id=userB.id,
        clearance_id=clearance_top.id,
        issued_at=datetime.now(),
        expired_at=datetime.now() + timedelta(days=1),
        issued_by=userB.id,
        signature=jwtB_cl
    )
    session.add(tokenB)
    session.commit()

    jwtB = create_access_token({"sub": userB.user_name, "id": userB.id})

    # -----------------------------
    # 4) User B downloads successfully
    # -----------------------------
    resp = client.get(f"/api/download/{file_uid}", headers={"Authorization": f"Bearer {jwtB}", "X-Clearance-Token": jwtB_cl})
    assert resp.status_code == 200

    iv_dl = base64.b64decode(resp.headers["X-IV"])
    tag_dl = base64.b64decode(resp.headers["X-Tag"])
    decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv_dl, tag_dl)).decryptor()
    plaintext = decryptor.update(resp.content) + decryptor.finalize()

    assert plaintext == b"accessible secret public file"

    file_path.unlink(missing_ok=True)


# =========================================================================================
# TEST — TRUSTED OFFICER BYPASS WITH REASON (SHOULD SUCCEED - bypasses MLS write-down)
# =========================================================================================

def test_trusted_officer_bypass_with_reason(client: TestClient, admin_token, session: Session):
    """
    Test that a TRUSTED_OFFICER with a reason can bypass MLS (write-down allowed).
    User has TOP_SECRET clearance but uploads a SECRET file - normally this would be denied (write-down).
    With TRUSTED_OFFICER role + reason, it should succeed.
    """
    # Create user first (needed for department created_by)
    hashed_password, salt = hash_password("password")
    userA = User(
        user_name="trusted_officer_user",
        hash_password=hashed_password,
        salt=salt,
        is_activated=True
    )
    session.add(userA)
    session.commit()
    session.refresh(userA)
    
    # Create department
    department = Department(name="trusted_test_dept", created_at=datetime.now(), created_by=userA.id)
    session.add(department)
    session.commit()
    session.refresh(department)
    
    # Create TRUSTED_OFFICER role token for this user and department
    create_role_token_for_user(session, userA.id, "TRUSTED_OFFICER", department.id)
    
    # Create TOP_SECRET clearance token for this user
    top_secret = session.exec(select(Clearance).where(Clearance.name == "TOP_SECRET")).first()
    # We need a private key for userA to sign the clearance token
    priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Update user with public key
    pub_pem = priv_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    userA.assymetric_public_key = pub_pem
    session.add(userA)
    session.commit()

    jwt_token = create_clearance_jwt(userA.id, top_secret.id, priv_key)

    clearance_token = ClearanceTokens(
        user_id=userA.id,
        clearance_id=top_secret.id,
        token_status="ACTIVE",
        issued_at=datetime.now(timezone.utc),
        expired_at=datetime.now(timezone.utc) + timedelta(days=7),
        reason="test_bypass",
        approver_id=userA.id,
        signature=jwt_token
    )
    session.add(clearance_token)
    session.commit()
    session.refresh(clearance_token)
    
    # Associate clearance token with department
    clearance_dept = ClearanceDepartment(clearance_token_id=clearance_token.id, department_id=department.id)
    session.add(clearance_dept)
    session.commit()
    
    # Login user
    jwtA = create_access_token({"sub": userA.user_name, "id": userA.id})
    
    # Prepare file with SECRET clearance (lower than user's TOP_SECRET - normally write-down denied)
    file_content = b"trusted officer bypass test"
    
    # Encrypt file
    aes_key = os.urandom(32)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(file_content) + encryptor.finalize()
    tag = encryptor.tag
    
    # Upload with reason - should SUCCEED because trusted officer with reason bypasses MLS
    response = client.post(
        "/api/transfers/",
        files={"file": ("bypass_test.txt", encrypted_data, "application/octet-stream")},
        data={
            "clearance_level": "SECRET",  # Lower than TOP_SECRET - write-down
            "department_list": str(department.id),
            "is_private": "false",
            "reason": "Emergency security review requires file at SECRET level",  # Reason provided!
            "aes_iv": base64.b64encode(iv).decode(),
            "aes_tag": base64.b64encode(tag).decode()
        },
        headers={"Authorization": f"Bearer {jwtA}"}
    )
    
    assert response.status_code == 200, f"Expected success but got: {response.json()}"
    
    # Clean up file
    file_ref = response.json().get("reference_to_file")
    if file_ref:
        Path(file_ref).unlink(missing_ok=True)


# =========================================================================================
# TEST — TRUSTED OFFICER BYPASS WITHOUT REASON (SHOULD FAIL)
# =========================================================================================

def test_trusted_officer_bypass_without_reason(client: TestClient, admin_token, session: Session):
    """
    Test that a TRUSTED_OFFICER WITHOUT a reason cannot bypass MLS.
    User has only TRUSTED_OFFICER role (not STANDARD_USER) for the department.
    Without a reason, the upload should be DENIED.
    """
    # Create user first (needed for department created_by)
    hashed_password, salt = hash_password("password")
    userA = User(
        user_name="trusted_no_reason_user",
        hash_password=hashed_password,
        salt=salt,
        is_activated=True
    )
    session.add(userA)
    session.commit()
    session.refresh(userA)
    
    # Create department
    department = Department(name="trusted_no_reason_dept", created_at=datetime.now(), created_by=userA.id)
    session.add(department)
    session.commit()
    session.refresh(department)
    
    # Create ONLY TRUSTED_OFFICER role token (not STANDARD_USER!)
    create_role_token_for_user(session, userA.id, "TRUSTED_OFFICER", department.id)
    
    # Create clearance token for this user
    secret = session.exec(select(Clearance).where(Clearance.name == "SECRET")).first()
    # We need a private key for userA to sign the clearance token
    priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Update user with public key
    pub_pem = priv_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    userA.assymetric_public_key = pub_pem
    session.add(userA)
    session.commit()

    jwt_token = create_clearance_jwt(userA.id, secret.id, priv_key)

    clearance_token = ClearanceTokens(
        user_id=userA.id,
        clearance_id=secret.id,
        token_status="ACTIVE",
        issued_at=datetime.now(timezone.utc),
        expired_at=datetime.now(timezone.utc) + timedelta(days=7),
        reason="test",
        approver_id=userA.id,
        signature=jwt_token
    )
    session.add(clearance_token)
    session.commit()
    session.refresh(clearance_token)
    
    # Associate clearance token with department
    clearance_dept = ClearanceDepartment(clearance_token_id=clearance_token.id, department_id=department.id)
    session.add(clearance_dept)
    session.commit()
    
    # Login user
    jwtA = create_access_token({"sub": userA.user_name, "id": userA.id})
    
    # Prepare file
    file_content = b"no reason test"
    
    # Encrypt file
    aes_key = os.urandom(32)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(file_content) + encryptor.finalize()
    tag = encryptor.tag
    
    # Upload WITHOUT reason - should FAIL because trusted officer needs reason
    response = client.post(
        "/api/transfers/",
        files={"file": ("no_reason_test.txt", encrypted_data, "application/octet-stream")},
        data={
            "clearance_level": "SECRET",
            "department_list": str(department.id),
            "is_private": "false",
            "reason": "",  # NO REASON!
            "aes_iv": base64.b64encode(iv).decode(),
            "aes_tag": base64.b64encode(tag).decode()
        },
        headers={"Authorization": f"Bearer {jwtA}"}
    )
    
    print("Trusted Officer WITHOUT reason response:", response.json())
    assert response.status_code == 400, f"Expected 400 but got {response.status_code}: {response.json()}"
