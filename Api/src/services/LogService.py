from sqlmodel import Session, select,and_,or_,func

from datetime import  datetime,timezone
import hashlib

from src.models.Logs import Logs
from src.models.RoleToken import RoleToken
from src.models.Role import Role, RoleType
from src.services.UserService import UserService
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization ,hashes
import base64


class LogService:
    
    user_service=UserService()
    
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
        
        # Use consistent timestamp format for hashing
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


    def check_if_auditor(self,session: Session,
        user_id: int,)->bool:
        tokens = session.exec(select(RoleToken).join(Role,RoleToken.role_id==Role.id)
                              .where(
                                  and_(
                                    user_id==RoleToken.user_id,
                                    Role.role==RoleType.AUDITOR))).first()
        
        return tokens is not None


    def verify_log_integrity(self,log: Logs, expected_previous_hash: str) -> bool:
        
        # Use consistent timestamp format for hashing
        formatted_timestamp = self._format_timestamp_for_hash(log.time_stamp)
        hash_input = f"{log.action}|{formatted_timestamp}|{log.description}|{log.user_id}|{expected_previous_hash}"
        print(hash_input)
        recalculated_hash = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
        return recalculated_hash == log.current_hash
    

    def sign_log(
        self,
        *,
        session: Session,

        user_id: int,
        log_id: int,
        signed_object: bytes
    ):
        if( not self.check_if_auditor(session=session,user_id=user_id)):
            self._create_log_entry(
                session=session,
                action="CHECK_AUDITOR_FAIL",
                description=f"User {user_id} doesnt have a AUDITOR role active",
                user_id=user_id
            )
            return None, "User doesnt have AUDITOR role active"
        log = session.exec(select(Logs).where(Logs.id==log_id)).first()
        if not log: 
            self._create_log_entry(
                session=session,
                action="SIGN_LOG_FAIL",
                description=f"User {user_id} tried to sign a log that doesnt exist",
                user_id=user_id
            )
            return None, "Log does not exist"
        # check signed_object
        resp = self.user_service.get_assymetric(session=session,user_id=user_id)
        if not resp:
            self._create_log_entry(
                session=session,
                action="SIGN_LOG_FAIL",
                description=f"User {user_id} doesnt have a public key",
                user_id=user_id
            )
            return None, "User doesnt have a public key"
        public_key = serialization.load_pem_public_key(resp.assymetric_public_key.encode())
        # cehck if this matches
        try:
            public_key.verify(
                signed_object,  
                log.current_hash.encode('utf-8'), 
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
        except Exception as e:
            self._create_log_entry(
                session=session,
                action="SIGN_LOG_FAIL",
                description=f"User {user_id} tried to sign a log with a signature that doesnt match that log",
                user_id=user_id
            )
            return None, "Signature does not match the log hash"
        logs = session.exec(select(Logs).where(Logs.id<=log_id)).all()
        # check all before so that i dont sig somethin wrong
        altered_logs =[]

        for i in range(len(logs) - 1, 0, -1):
            if logs[i].previous_hash != logs[i - 1].current_hash:
                altered_logs.append(logs[i])
                break
            elif not self.verify_log_integrity(logs[i], logs[i - 1].current_hash):
                altered_logs.append(logs[i])
                break
        if altered_logs:
            self._create_log_entry(
                            session=session,
                            action="FAIL_SIGN_LOG",
                            description=f"User {user_id} tried to sign logs but logs until that point are alredy check again",
                            user_id=user_id
                        )
            return None, "Log chain integrity check failed - logs were altered"


        log.check_by=user_id
        log.check_at=datetime.now()
        log.signature=base64.b64encode(signed_object).decode()
        session.add(log)
        session.commit()
        session.refresh(log)
        return log, None

        
    def get_logs(
        self,
        *,
        session: Session,

        user_id: int,

    ):
        if( not self.check_if_auditor(session=session,user_id=user_id)):
            self._create_log_entry(
                session=session,
                action="CHECK_AUDITOR_FAIL",
                description=f"User {user_id} doesnt have a AUDITOR role active",
                user_id=user_id
            )
            return None,None

        self._create_log_entry(
                session=session,
                action="RETRIEVE_LOGS_SUCESS",
                description=f"User {user_id} retrieved logs",
                user_id=user_id
            )
        logs = session.exec(select(Logs)).all()
        altered_logs =[]
        for i in range(1,len(logs)):
            print(i)
            if logs[len(logs)-i].previous_hash != logs[len(logs) -i - 1].current_hash:

                self._create_log_entry(
                        session=session,
                        action="RETRIEVE_LOGS_WERE_ALTERED",
                        description=f"User {user_id} retrieved logs but log {logs[i]} and {logs[i-1]} have a mistach",
                        user_id=user_id
                    )
                altered_logs.append(logs[len(logs) -i])
            elif not self.verify_log_integrity(logs[len(logs) -i], logs[len(logs) -i - 1].current_hash):
                altered_logs.append(logs[len(logs) -i])
        return logs,altered_logs