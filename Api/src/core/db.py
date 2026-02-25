from sqlmodel import create_engine, SQLModel, select, Session
from src.core.settings import settings
from src.core.security import hash_password, ALGORITHM
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import sqlite3
import jwt
from src.core.generate_keys import load_or_generate_server_keys

def adapt_datetime(val):
    return val.isoformat(" ")

sqlite3.register_adapter(datetime, adapt_datetime)

from src.models.Clearance import Clearance
from src.models.ClearanceDepartment import ClearanceDepartment
from src.models.ClearanceRevocations import ClearanceRevocations
from src.models.ClearanceToken import ClearanceTokens,TokenStatus
from src.models.Department import Department
from src.models.EncryptedFileKeys import EncryptedFileKeys
from src.models.File import File
from src.models.FileDepartment import FileDepartment
from src.models.Logs import Logs
from src.models.Role import Role
from src.models.RoleRevocation import RoleRevocation
from src.models.RoleToken import RoleToken
from src.models.User import User
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
        

# PRIVATE_KEY, PUBLIC_KEY = load_or_generate_server_keys()


engine = create_engine(str(settings.DATABASE_URI), echo=True)

def init_db():
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:

        # --- CLEARANCE ---
        clearance_levels = ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP_SECRET"]
        for level in clearance_levels:
            existing_clearance = session.exec(select(Clearance).where(Clearance.name == level)).first()
            if not existing_clearance:
                new_clearance = Clearance(name=level)
                session.add(new_clearance)
                session.commit()
                session.refresh(new_clearance)
                print(f"Clearance created: {new_clearance.id} - {new_clearance.name}")
        
        # --- ROLES ---
        role_names = ["ADMINISTRATOR", "SECURITY_OFFICER", "TRUSTED_OFFICER", "STANDARD_USER", "AUDITOR"]
        for role_name in role_names:
            existing_role = session.exec(select(Role).where(Role.role == role_name)).first()
            if not existing_role:
                new_role = Role(role=role_name)
                session.add(new_role)
                session.commit()
                session.refresh(new_role)
                print(f"Role created: {new_role.id} - {new_role.role}")
        
        admin_user = session.exec(select(User).where(User.user_name == "admin")).first()
        if not admin_user:
            # Generate keys only if creating new admin
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
            
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode("utf-8")

            hashed_password, salt = hash_password("admin")

            admin_user = User(
                user_name="admin",
                hash_password=hashed_password,
                salt=salt,
                assymetric_public_key=public_pem,
                is_activated=True,
                last_login=datetime.now(timezone.utc)
            )
            session.add(admin_user)
            session.commit()
            session.refresh(admin_user)

            # Create Blob
            admin_password = "admin"
            pem_data = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            salt = os.urandom(16)
            nonce = os.urandom(12)
            
            kdf = Argon2id(
                salt=salt,
                length=32,
                iterations=3,
                lanes=4,
                memory_cost= 262144
            )
            aes_key = kdf.derive(admin_password.encode())
            
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(pem_data) + encryptor.finalize()
            tag = encryptor.tag
            
            blob = salt + nonce + ciphertext + tag
            
            admin_user.blob = blob
            session.add(admin_user)
            session.commit()
            session.refresh(admin_user)

            # Create Token
            admin_role = session.exec(select(Role).where(Role.role == "ADMINISTRATOR")).first()
            
            admin_role_payload = {
                "sub": str(admin_user.id),
                "iss": str(admin_user.id),
                "role_id": admin_role.id,
                "iat": int(datetime.now(timezone.utc).timestamp())
            }

            admin_role_signature = jwt.encode(admin_role_payload, private_key, algorithm=ALGORITHM)

            admin_role_token = RoleToken(
                user_id=admin_user.id,
                role_id=admin_role.id,
                issued_at=datetime.now(timezone.utc),
                issued_by=admin_user.id,  # Self-issued
                token_status=TokenStatus.ACTIVE.value,
                signature=admin_role_signature,
                status="ACTIVE"
            )
            session.add(admin_role_token)
            session.commit()
            session.refresh(admin_role_token)

        # --- AUDITOR USER ---
        auditor_user = session.exec(select(User).where(User.user_name == "auditor")).first()
        if not auditor_user:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode("utf-8")

            hashed_password, salt = hash_password("auditor")

            auditor_user = User(
                user_name="auditor",
                hash_password=hashed_password,
                salt=salt,
                assymetric_public_key=public_pem,
                is_activated=True,
                last_login=datetime.now(timezone.utc)
            )
            session.add(auditor_user)
            session.commit()
            session.refresh(auditor_user)

            # Create Blob for auditor
            auditor_password = "auditor"
            pem_data = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            salt = os.urandom(16)
            nonce = os.urandom(12)
            
            kdf = Argon2id(
                salt=salt,
                length=32,
                iterations=3,
                lanes=4,
                memory_cost=262144
            )
            aes_key = kdf.derive(auditor_password.encode())
            
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(pem_data) + encryptor.finalize()
            tag = encryptor.tag
            
            blob = salt + nonce + ciphertext + tag
            
            auditor_user.blob = blob
            session.add(auditor_user)
            session.commit()
            session.refresh(auditor_user)

            # Create AUDITOR role token
            auditor_role = session.exec(select(Role).where(Role.role == "AUDITOR")).first()
            admin_user_for_signing = session.exec(select(User).where(User.user_name == "admin")).first()
            
            auditor_role_payload = {
                "sub": str(auditor_user.id),
                "iss": str(admin_user_for_signing.id),
                "role_id": auditor_role.id,
                "iat": int(datetime.now(timezone.utc).timestamp())
            }

            auditor_role_signature = jwt.encode(auditor_role_payload, private_key, algorithm=ALGORITHM)

            auditor_role_token = RoleToken(
                user_id=auditor_user.id,
                role_id=auditor_role.id,
                issued_at=datetime.now(timezone.utc),
                issued_by=admin_user_for_signing.id,
                token_status=TokenStatus.ACTIVE.value,
                signature=auditor_role_signature,
                status="ACTIVE"
            )
            session.add(auditor_role_token)
            session.commit()
            session.refresh(auditor_role_token)

        # --- AUTHENTICATED USER ---
        auth_user = session.exec(select(User).where(User.user_name == "authenticated_user")).first()
        if not auth_user:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode("utf-8")

            hashed_password, salt = hash_password("authenticated user")

            auth_user = User(
                user_name="authenticated_user",
                hash_password=hashed_password,
                salt=salt,
                assymetric_public_key=public_pem,
                is_activated=True,
                last_login=datetime.now(timezone.utc)
            )
            session.add(auth_user)
            session.commit()
            session.refresh(auth_user)

            # Create Blob for authenticated_user
            auth_password = "authenticated user"
            pem_data = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            salt = os.urandom(16)
            nonce = os.urandom(12)
            
            kdf = Argon2id(
                salt=salt,
                length=32,
                iterations=3,
                lanes=4,
                memory_cost=262144
            )
            aes_key = kdf.derive(auth_password.encode())
            
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(pem_data) + encryptor.finalize()
            tag = encryptor.tag
            
            blob = salt + nonce + ciphertext + tag
            
            auth_user.blob = blob
            session.add(auth_user)
            session.commit()
            session.refresh(auth_user)

            # Create STANDARD_USER role token for authenticated_user
            standard_role = session.exec(select(Role).where(Role.role == "STANDARD_USER")).first()
            admin_user_for_signing = session.exec(select(User).where(User.user_name == "admin")).first()
            
            auth_role_payload = {
                "sub": str(auth_user.id),
                "iss": str(admin_user_for_signing.id),
                "role_id": standard_role.id,
                "iat": int(datetime.now(timezone.utc).timestamp())
            }

            auth_role_signature = jwt.encode(auth_role_payload, private_key, algorithm=ALGORITHM)

            auth_role_token = RoleToken(
                user_id=auth_user.id,
                role_id=standard_role.id,
                issued_at=datetime.now(timezone.utc),
                issued_by=admin_user_for_signing.id,
                token_status=TokenStatus.ACTIVE.value,
                signature=auth_role_signature,
                status="ACTIVE"
            )
            session.add(auth_role_token)
            session.commit()
            session.refresh(auth_role_token)

        # --- USER1 (STANDARD_USER with SECRET clearance) ---
        user1 = session.exec(select(User).where(User.user_name == "user1")).first()
        if not user1:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode("utf-8")

            hashed_password, salt = hash_password("user1")

            user1 = User(
                user_name="user1",
                hash_password=hashed_password,
                salt=salt,
                assymetric_public_key=public_pem,
                is_activated=True,
                last_login=datetime.now(timezone.utc)
            )
            session.add(user1)
            session.commit()
            session.refresh(user1)

            # Create Blob for user1
            user1_password = "user1"
            pem_data = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            salt = os.urandom(16)
            nonce = os.urandom(12)
            
            kdf = Argon2id(
                salt=salt,
                length=32,
                iterations=3,
                lanes=4,
                memory_cost=262144
            )
            aes_key = kdf.derive(user1_password.encode())
            
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(pem_data) + encryptor.finalize()
            tag = encryptor.tag
            
            blob = salt + nonce + ciphertext + tag
            
            user1.blob = blob
            session.add(user1)
            session.commit()
            session.refresh(user1)

            # Create STANDARD_USER role token for user1
            standard_role = session.exec(select(Role).where(Role.role == "STANDARD_USER")).first()
            admin_user_for_signing = session.exec(select(User).where(User.user_name == "admin")).first()
            
            user1_role_payload = {
                "sub": str(user1.id),
                "iss": str(admin_user_for_signing.id),
                "role_id": standard_role.id,
                "iat": int(datetime.now(timezone.utc).timestamp())
            }

            user1_role_signature = jwt.encode(user1_role_payload, private_key, algorithm=ALGORITHM)

            user1_role_token = RoleToken(
                user_id=user1.id,
                role_id=standard_role.id,
                issued_at=datetime.now(timezone.utc),
                issued_by=admin_user_for_signing.id,
                token_status=TokenStatus.ACTIVE.value,
                signature=user1_role_signature,
                status="ACTIVE"
            )
            session.add(user1_role_token)
            session.commit()
            session.refresh(user1_role_token)

            # Create SECRET clearance token for user1
            # Signed by user1 themselves (self-issued clearance token)
            secret_clearance = session.exec(select(Clearance).where(Clearance.name == "SECRET")).first()
            
            clearance_payload = {
                "iss": str(user1.id),  # Self-signed - issuer is user1
                "sub": str(user1.id),
                "clearance_id": secret_clearance.id,
                "iat": int(datetime.now(timezone.utc).timestamp()),
                "exp": int((datetime.now(timezone.utc) + timedelta(days=365)).timestamp())
            }
            
            clearance_signature = jwt.encode(clearance_payload, private_key, algorithm=ALGORITHM)
            
            user1_clearance_token = ClearanceTokens(
                user_id=user1.id,
                clearance_id=secret_clearance.id,
                issued_at=datetime.now(timezone.utc),
                expired_at=datetime.now(timezone.utc) + timedelta(days=365),
                issued_by=user1.id,  # Self-issued
                token_status=TokenStatus.ACTIVE.value,
                signature=clearance_signature
            )
            session.add(user1_clearance_token)
            session.commit()
            session.refresh(user1_clearance_token)

        # --- SECURITY OFFICER USER ---
        security_user = session.exec(select(User).where(User.user_name == "security")).first()
        if not security_user:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode("utf-8")

            hashed_password, salt = hash_password("security")

            security_user = User(
                user_name="security",
                hash_password=hashed_password,
                salt=salt,
                assymetric_public_key=public_pem,
                is_activated=True,
                last_login=datetime.now(timezone.utc)
            )
            session.add(security_user)
            session.commit()
            session.refresh(security_user)

            # Create Blob for security_officer
            security_password = "security"
            pem_data = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            salt = os.urandom(16)
            nonce = os.urandom(12)
            
            kdf = Argon2id(
                salt=salt,
                length=32,
                iterations=3,
                lanes=4,
                memory_cost=262144
            )
            aes_key = kdf.derive(security_password.encode())
            
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(pem_data) + encryptor.finalize()
            tag = encryptor.tag
            
            blob = salt + nonce + ciphertext + tag
            
            security_user.blob = blob
            session.add(security_user)
            session.commit()
            session.refresh(security_user)

            # Create SECURITY_OFFICER role token
            security_role = session.exec(select(Role).where(Role.role == "SECURITY_OFFICER")).first()
            
            security_role_payload = {
                "sub": str(security_user.id),
                "iss": str(security_user.id),  # Self-signed
                "role_id": security_role.id,
                "iat": int(datetime.now(timezone.utc).timestamp())
            }

            security_role_signature = jwt.encode(security_role_payload, private_key, algorithm=ALGORITHM)

            security_role_token = RoleToken(
                user_id=security_user.id,
                role_id=security_role.id,
                issued_at=datetime.now(timezone.utc),
                issued_by=security_user.id,  # Self-issued
                token_status=TokenStatus.ACTIVE.value,
                signature=security_role_signature,
                status="ACTIVE"
            )
            session.add(security_role_token)
            session.commit()
            session.refresh(security_role_token)
