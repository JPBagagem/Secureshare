from sqlmodel import Session, select
from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException
import hashlib
import secrets
import string
from datetime import datetime, timezone, timedelta
from src.models.User import User, UserCreate, UserCreatedResponse, UserActivate, UserLogin, UserInfoUpdate, LoginResponse, PublicKeyResponse
from src.models.Role import Role, RoleType
from src.models.RoleToken import RoleToken, RoleTokenCreate, RoleTokenResponse
from src.models.RoleRevocation import RoleRevocation, RoleRevocationRequest
from src.models.ClearanceToken import ClearanceTokens, ClearanceTokenResponse, ClearanceTokenRequest, TokenStatus
from src.models.ClearanceDepartment import ClearanceDepartment
from src.models.Clearance import Clearance
from src.models.ClearanceRevocations import ClearanceRevocations
from src.models.Logs import Logs
import jwt
from src.core.security import ALGORITHM
from cryptography.hazmat.primitives import serialization

from src.core.security import hash_password, verify_password, create_access_token

class UserService:

    def _format_timestamp_for_hash(self, timestamp: datetime) -> str:
        """Ensure consistent timestamp format for hash calculation.
        
        This removes timezone info and uses a fixed format to ensure
        the hash is the same before and after database round-trip.
        """
        # Use a naive datetime (no timezone) with fixed precision
        if timestamp.tzinfo is not None:
            # Convert to UTC and remove timezone info
            timestamp = timestamp.replace(tzinfo=None)
        # Use a consistent format without timezone
        return timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")
    

    def _create_log_entry(
        self,
        session: Session,
        action: str,
        description: str,
        user_id: int
    ) -> None:

        # gets last has        
        last_log = session.exec(
            select(Logs)
            .order_by(Logs.id.desc()) 
            .limit(1)
        ).first()
        
        previous_hash = last_log.current_hash if last_log else "first"
        
        timestamp = datetime.now(timezone.utc)
        formatted_timestamp = self._format_timestamp_for_hash(timestamp)
        hash_input = f"{action}|{formatted_timestamp}|{description}|{user_id}|{previous_hash}"
        current_hash = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
        
        log = Logs(
            action=action,
            time_stamp=timestamp,
            description=description,
            user_id=user_id,
            previous_hash=previous_hash,
            current_hash=current_hash
        )
        
        session.add(log)
        session.commit()

    def create_user(self, session: Session, user_create: UserCreate) -> UserCreatedResponse:
        # Generate random password
        alphabet = string.ascii_letters + string.digits
        password = ''.join(secrets.choice(alphabet) for i in range(12))

        # Hash password using Argon2id
        hashed_password, salt = hash_password(password)

        # Create user object
        user = User.model_validate(user_create)
        user.hash_password = hashed_password
        user.salt = salt
        
        session.add(user)
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            raise HTTPException(status_code=409, detail="User already exists")
        session.refresh(user)
        
        self._create_log_entry(
            session=session,
            action="CREATE_USER",
            description=f"User {user.user_name} created",
            user_id=user.id
        )
        session.refresh(user)
        
        # Return response with raw password
        user_dict = user.model_dump()
        user_dict["password"] = password
        user_dict["id"] = user.id
        response = UserCreatedResponse.model_validate(user_dict)
        return response

    def activate_user(self, session: Session, user_activate: UserActivate) -> User:
        user = session.exec(select(User).where(User.user_name == user_activate.user_name)).first()
        
        if not user:
            return None
            
        if user.is_activated:
            return user

        if not verify_password(user_activate.one_time_password, user.salt, user.hash_password):
            return None

        # Hash new password
        new_hashed_password, new_salt = hash_password(user_activate.password)

        user.is_activated = True
        user.hash_password = new_hashed_password
        user.salt = new_salt
        user.assymetric_public_key = user_activate.assymetric_public_key
        session.add(user)
        session.commit()
        session.refresh(user)

        self._create_log_entry(
            session=session,
            action="ACTIVATE_USER",
            description=f"User {user.user_name} activated",
            user_id=user.id
        )
        
        # Get reference to AUDITOR role for later use
        standard_role = session.exec(select(Role).where(Role.role == RoleType.STANDARD_USER.value)).first()
    
        standard_role_token = session.exec(
            select(RoleToken)
            .where(RoleToken.user_id == user.id)
            .where(RoleToken.role_id == standard_role.id)
        ).first()

        if not standard_role_token:
            standard_role_token = RoleToken(
                user_id=user.id,
                role_id=standard_role.id,
                expired_at=datetime.now(timezone.utc) + timedelta(days=999999),  # Sem expiração para admin
                issued_at=datetime.now(timezone.utc),
                issued_by=user.id,  # Self-issued
                token_status=TokenStatus.ACTIVE.value,
                signature="user_signature_initial",
                status="ACTIVE"
            )
            session.add(standard_role_token)
            session.commit()
            session.refresh(standard_role_token)
        
        return user

    def get_users(self, session: Session) -> list[User]:
        users = session.exec(select(User)).all()
        return users

    def login_user(self, session: Session, user_login: UserLogin) -> LoginResponse:
        user = session.exec(select(User).where(User.user_name == user_login.user_name)).first()
        if not user:
            return None
        
        if not verify_password(user_login.password, user.salt, user.hash_password):
            return None
        
        if not user.is_activated:
            return None
        
        # Fetch role tokens
        statement = select(RoleToken).where(RoleToken.user_id == user.id)
        role_tokens = session.exec(statement).all()
        
        access_token = create_access_token(data={"sub": user.user_name, "id": user.id})
        
        user.last_login = datetime.now(timezone.utc)
        session.add(user)
        session.commit()
        session.refresh(user)
        
        self._create_log_entry(
            session=session,
            action="LOGIN_USER",
            description=f"User {user.user_name} logged in",
            user_id=user.id
        )
        
        # Fetch clearance tokens
        clearance_tokens_response = self.get_clearance_tokens(session, user.id)

        return LoginResponse(
            access_token=access_token, 
            token_type="bearer",
            user_id=user.id,    
            role_tokens={session.exec(select(Role).where(Role.id == rt.role_id)).first().role: RoleTokenResponse.model_validate(rt) for rt in role_tokens},
            clearance_tokens=[
                ClearanceTokenResponse(
                    clearance_name=session.exec(select(Clearance).where(Clearance.id == cl_token.clearance_id)).first().name,
                    departments=session.exec(select(ClearanceDepartment.department_id).where(ClearanceDepartment.clearance_token_id == cl_token.id)).all(),
                    id=cl_token.id,
                    user_id=cl_token.user_id,
                    clearance_id=cl_token.clearance_id,
                    expired_at=cl_token.expired_at,
                    issued_at=cl_token.issued_at,
                    issued_by=cl_token.issued_by,
                    token_status=cl_token.token_status,
                    signature=cl_token.signature,
                ) for cl_token in clearance_tokens_response
            ]
        )

    def update_vault(self, session: Session, user: User, blob: str) -> None:
        user.blob = blob
        session.add(user)
        session.commit()
        session.refresh(user)
        
        self._create_log_entry(
            session=session,
            action="UPDATE_VAULT",
            description=f"User {user.user_name} updated vault",
            user_id=user.id
        )

    def update_user_info(self, session: Session, user: User, user_update: UserInfoUpdate) -> User:
        if user_update.user_name:
            user.user_name = user_update.user_name

        if user_update.password:
            hashed_password, salt = hash_password(user_update.password)
            user.hash_password = hashed_password
            user.salt = salt
            
        session.add(user)
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            raise HTTPException(status_code=409, detail="Username already exists")
            
        session.refresh(user)
        
        self._create_log_entry(
            session=session,
            action="UPDATE_USER_INFO",
            description=f"User {user.user_name} updated info",
            user_id=user.id
        )
        
        return user
    
    def get_assymetric(self,session:Session,user_id:int):
        return PublicKeyResponse(assymetric_public_key=session.exec(
            select(User.assymetric_public_key).where(User.id == user_id)
        ).first())
    

    def add_role_token(self, session: Session, user_id: int, role_token_create: RoleTokenCreate, granter_id: int) -> RoleToken:
        # 1. Verify that the user exists
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # 2. Verify that the granter (issued_by) exists and get their public key
        granter = session.get(User, granter_id)
        if not granter:
            raise HTTPException(status_code=404, detail="Granter not found")
        
        if not granter.assymetric_public_key:
             raise HTTPException(status_code=400, detail="Granter has no public key")
        
        # 3. Verify JWT signature and claims
        try:

            key_obj = serialization.load_pem_public_key(
                granter.assymetric_public_key.encode('utf-8')  # convert string to bytes
            )
            
            # Decode and verify signature using granter's public key
            payload = jwt.decode(role_token_create.signature, key_obj, algorithms=[ALGORITHM])
            
            # Verify claims
            if payload.get("sub") != str(user_id):
                 raise HTTPException(status_code=400, detail="Token subject does not match target user")
            
            # if payload.get("role_type") != role_token_create.role_id:
            #      raise HTTPException(status_code=400, detail="Token role_id does not match request")
                 
            # if payload.get("dept_id") != role_token_create.department_id:
            #      raise HTTPException(status_code=400, detail="Token department_id does not match request")
                 
            if payload.get("iss") != str(granter_id):
                 raise HTTPException(status_code=400, detail="Token issuer does not match granter")
        
            role_type = payload.get("role_type")
            role_id = session.exec(select(Role).where(Role.role == role_type)).first()
            if not role_id:
                raise HTTPException(status_code=400, detail="Token missing clearance_id")
            
            # 4. Create and save the RoleToken
            role_token = RoleToken(
                user_id=user_id,
                role_id=role_id.id,
                department_id=payload.get("dept_id"),
                issued_by=granter_id,
                issued_at=datetime.fromisoformat(payload.get("iat")) if isinstance(payload.get("iat"), str) else datetime.fromtimestamp(payload.get("iat"), tz=timezone.utc),
                signature=role_token_create.signature
            )
            
            session.add(role_token)
            session.commit()
            session.refresh(role_token)
            
            self._create_log_entry(
                session=session,
                action="ADD_ROLE",
                description=f"Role {role_token.role_id} added to user {user_id} by {role_token.issued_by}",
                user_id=user_id
            )
            
            return role_token

        except jwt.PyJWTError as e:
            raise HTTPException(status_code=400, detail=f"Invalid token: {str(e)}")

    

    def revoke_token(self, session: Session, user_id: int, token_id: int, revocation_request: RoleRevocationRequest, revoker_id: int):
        # 1. Verify that the user exists
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # 2. Verify that the revoker exists and get their public key
        revoker = session.get(User, revoker_id)
        if not revoker:
            raise HTTPException(status_code=404, detail="Revoker not found")
        
        if not revoker.assymetric_public_key:
             raise HTTPException(status_code=400, detail="Revoker has no public key")

        # 3. Determine Token Type and Verify Existence

        token_type = None
        try:
            # Decode without verification to get type claim if possible
            unverified_payload = jwt.decode(revocation_request.signature, options={"verify_signature": False})
            token_type = unverified_payload.get("type")
        except jwt.PyJWTError:
            pass # Proceed to ambiguity check if decoding fails or type missing

        role_token = session.get(RoleToken, token_id)
        clearance_token = session.get(ClearanceTokens, token_id)

        target_token = None
        is_role = False

        if token_type == "role":
            if not role_token:
                 raise HTTPException(status_code=404, detail="Role token not found")
            target_token = role_token
            is_role = True
        elif token_type == "clearance":
            if not clearance_token:
                 raise HTTPException(status_code=404, detail="Clearance token not found")
            target_token = clearance_token
            is_role = False
        else:
            # Ambiguity Resolution
            if role_token and clearance_token:
                raise HTTPException(status_code=400, detail="Ambiguous token ID. Please specify token type in revocation signature.")
            elif role_token:
                target_token = role_token
                is_role = True
            elif clearance_token:
                target_token = clearance_token
                is_role = False
            else:
                raise HTTPException(status_code=404, detail="Token not found")

        # 4. Verify Token Ownership
        if target_token.user_id != user_id:
            raise HTTPException(status_code=400, detail="Token does not belong to the specified user")

        if is_role:
             # Verify that the token is not an Administrator token
            role_obj = session.get(Role, target_token.role_id)
            if role_obj.role == RoleType.ADMINISTRATOR:
                raise HTTPException(status_code=403, detail="Not authorized to revoke Administrator roles")

        # 5. Verify JWT signature and claims
        try:
            # Decode and verify signature using revoker's public key
            payload = jwt.decode(revocation_request.signature, revoker.assymetric_public_key, algorithms=[ALGORITHM])
            
            # Verify claims
            if payload.get("sub") != str(token_id):
                 raise HTTPException(status_code=400, detail="Token subject does not match target token id")
            
            if payload.get("iss") != str(revoker_id):
                 raise HTTPException(status_code=400, detail="Token issuer does not match revoker")
                 
        except jwt.PyJWTError as e:
            raise HTTPException(status_code=400, detail=f"Invalid token: {str(e)}")

        # 6. Create Revocation Entry and Update Status
        if is_role:
            revocation = RoleRevocation(
                revoked_by=revoker_id,
                role_token=token_id,
                revoked_at=revocation_request.revoked_at,
                signature=revocation_request.signature
            )
            session.add(revocation)
            target_token.status = "REVOKED"
            session.add(target_token)
            
            self._create_log_entry(
                session=session,
                action="REVOKE_ROLE",
                description=f"Role token {token_id} revoked for user {user_id} by {revoker_id}",
                user_id=user_id
            )
            return revocation
        else:
            revocation = ClearanceRevocations(
                revoked_by=revoker_id,
                clearance_token_id=token_id,
                revoked_at=revocation_request.revoked_at,
                signature=revocation_request.signature
            )
            session.add(revocation)
            target_token.token_status = TokenStatus.REVOKED.value
            session.add(target_token)
            
            self._create_log_entry(
                session=session,
                action="REVOKE_CLEARANCE",
                description=f"Clearance token {token_id} revoked for user {user_id} by {revoker_id}",
                user_id=user_id
            )
            return revocation

    def delete_user(self, session: Session, user_id: int) -> None:
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
            
        session.delete(user)
        session.commit()
        
        self._create_log_entry(
            session=session,
            action="DELETE_USER",
            description=f"User {user.user_name} deleted",
            user_id=user_id
        )

    def get_clearance_tokens(self, session: Session, user_id: int) -> list[ClearanceTokenResponse]:
        # Verify user exists
        user = session.get(User, user_id)
        if not user:
             raise HTTPException(status_code=404, detail="User not found")

        tokens = session.exec(select(ClearanceTokens).where(ClearanceTokens.user_id == user_id)).all()
        response = []
        for token in tokens:
            # Get departments
            depts = session.exec(select(ClearanceDepartment.department_id).where(ClearanceDepartment.clearance_token_id == token.id)).all()
            
            response.append(ClearanceTokenResponse(
                id=token.id,
                user_id=token.user_id,
                clearance_id=token.clearance_id,
                expired_at=token.expired_at,
                issued_at=token.issued_at,
                issued_by=token.issued_by,
                token_status=token.token_status,
                signature=token.signature,
                departments=depts,
                clearance_name=session.exec(select(Clearance).where(Clearance.id == token.clearance_id)).first().name
            ))
            
        return response

    def add_clearance_token(self, session: Session, user_id: int, token_request: ClearanceTokenRequest, granter_id: int) -> ClearanceTokenResponse:
        # 1. Verify that the user exists
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # 2. Verify that the granter (issued_by) exists and get their public key
        granter = session.get(User, granter_id)
        if not granter:
            raise HTTPException(status_code=404, detail="Granter not found")
        
        if not granter.assymetric_public_key:
             raise HTTPException(status_code=400, detail="Granter has no public key")
        
        # 3. Verify JWT signature and claims
        try:
            
            # Decode and verify signature using granter's public key
            # The token is the JWT itself
            payload = jwt.decode(token_request.token, granter.assymetric_public_key, algorithms=[ALGORITHM])
            
            # Verify claims
            if payload.get("sub") != str(user_id):
                 raise HTTPException(status_code=400, detail="Token subject does not match target user")
            
            if payload.get("iss") != str(granter_id):
                 raise HTTPException(status_code=400, detail="Token issuer does not match granter")
                 
            clearance_type = payload.get("clearance_type")
            clearance_id = session.exec(select(Clearance).where(Clearance.name == clearance_type)).first()
            if not clearance_id:
                raise HTTPException(status_code=400, detail="Token missing clearance_id")
                
            department_ids = payload.get("dept_ids", [])
            
            issued_at_timestamp = payload.get("iat")
            expired_at_timestamp = payload.get("exp")
            
            issued_at = datetime.fromtimestamp(issued_at_timestamp, tz=timezone.utc) if issued_at_timestamp else datetime.now(timezone.utc)
            expired_at = datetime.fromtimestamp(expired_at_timestamp, tz=timezone.utc) if expired_at_timestamp else None

        except jwt.PyJWTError as e:
            raise HTTPException(status_code=400, detail=f"Invalid token: {str(e)}")

        # 4. Create and save the ClearanceToken
        clearance_token = ClearanceTokens(
            user_id=user_id,
            clearance_id=clearance_id.id,
            issued_by=granter_id,
            issued_at=issued_at,
            signature=token_request.token, # Store the full JWT as the signature/token
            expired_at=expired_at,
            token_status=TokenStatus.ACTIVE.value
        )
        
        session.add(clearance_token)
        session.commit()
        session.refresh(clearance_token)
        
        # 5. Add departments
        for dept_id in department_ids:
            clearance_dept = ClearanceDepartment(
                clearance_token_id=clearance_token.id,
                department_id=dept_id
            )
            session.add(clearance_dept)
            
        session.commit()
        
        self._create_log_entry(
            session=session,
            action="ADD_CLEARANCE",
            description=f"Clearance {clearance_id} added to user {user_id} by {granter_id}",
            user_id=user_id
        )
        
        # Return response
        return ClearanceTokenResponse(
            id=clearance_token.id,
            user_id=clearance_token.user_id,
            clearance_id=clearance_token.clearance_id,
            expired_at=clearance_token.expired_at,
            issued_at=clearance_token.issued_at,
            issued_by=clearance_token.issued_by,
            token_status=clearance_token.token_status,
            signature=clearance_token.signature,
            departments=department_ids,
            clearance_name=clearance_id.name
        )
