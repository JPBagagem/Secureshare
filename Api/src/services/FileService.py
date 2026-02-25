from sqlmodel import Session, select,and_
import hashlib
from pathlib import Path
from datetime import  timezone,datetime,timedelta
from src.models.Department import Department
from src.models.File import File
from src.models.Role import Role, RoleType 

from src.models.Clearance import Clearance
from src.models.ClearanceToken import ClearanceTokens,TokenStatus
from src.models.ClearanceDepartment import ClearanceDepartment
from src.models.FileDepartment import FileDepartment
from src.models.Logs import Logs
from src.models.EncryptedFileKeys import EncryptedFileKeys
from src.models.RoleToken import RoleToken
import uuid
import base64

class FileService:

    UPLOAD_DIR = Path("uploads")
    EXPIRATION_DAYS = 3
    

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



    def __init__(self):
        # creates the dir to uploads
        self.UPLOAD_DIR.mkdir(exist_ok=True, parents=True)


    def upload_file(
        self,
        *,
        session: Session,

        user_id: int,
        file_name: str,
        is_privat:bool,
        clearance_level: str,
        user_clearance:ClearanceTokens,
        file_data:bytes,
        department_list:list[int],
        tag_bytes:bytes,
        iv_bytes:bytes,
        encrypted_key_bytes:bytes,
        reason:str
    ):
        trusted_officer = session.exec(select(Role).where(Role.role == RoleType.TRUSTED_OFFICER)).first()
        deps_set_security = session.exec(select(RoleToken.department_id).where(and_(RoleToken.user_id == user_id, RoleToken.role_id == trusted_officer.id))).all()
        clearance_id = session.exec(select(Clearance.id).where(Clearance.name == clearance_level)).first()
        permited=True
        print("\n\n\n\n")
        print(user_clearance)
        if user_clearance:
            deps = session.exec(select(ClearanceDepartment.department_id).where(ClearanceDepartment.clearance_token_id == user_clearance.id)).all()

            for n in deps:
                if n not in department_list:
                    permited=False
                    break
        else:
            permited=False
        print(permited)
        print(deps_set_security)
        print(reason)
        if not permited and deps_set_security:
            if not reason:
                self._create_log_entry(
                    session=session,
                    action="UPLOAD_DENIED",
                    description=f"User {user_id} try to upload file {file_name} but user dont have any role token for department {department_list}",
                    user_id=user_id
                )
                print("DEBUG: Returning early due to not permited (no reason)", flush=True)
                return
            
            deps_name = []

            for n in department_list:
                if n not in deps_set_security:
                    self._create_log_entry(
                        session=session,
                        action="UPLOAD_DENIED",
                        description=f"User {user_id} trusted officer try to upload file {file_name} but user dont have any reason",
                        user_id=user_id
                    )
                    return 
                deps_name.append(session.exec(select(Department.name).where(Department.id == n)).first())
        
        
            
            created_at = datetime.now(timezone.utc)
            expired_at = created_at + timedelta(days=3)
            
            file_url = self.UPLOAD_DIR / f"{uuid.uuid4()}.enc"
            
            file = File(
                file_name=file_name,
                clearance_id=clearance_id,
                reference_to_file=str(file_url),
                expire_at=expired_at,
                user_id=user_id,
                is_private=is_privat,
                symetric_key_encrypted= base64.b64encode(encrypted_key_bytes).decode() if encrypted_key_bytes else None,
                tag_bytes=tag_bytes,
                iv_bytes=iv_bytes,
                reason=reason
            )
            
            try:
                with open(file_url, "wb") as f:
                    f.write(file_data)
                session.add(file)
                session.commit()
                session.refresh(file)
                
                
                for dep in department_list:
                    file_dep = FileDepartment(file_uid=file.uid, department_id=dep)
                    session.add(file_dep)
                session.commit()

                # Log the bypass with reason
                self._create_log_entry(
                    session=session,
                    action="SECURITY_OFFICER_BYPASS_UPLOAD",
                    description=f"Security Officer {user_id} uploaded file {file_name} to {deps_name} bypassing MLS. Reason: {reason}",
                    user_id=user_id
                )
                
                return {
                    "uid": file.uid,
                    "file_name": file.file_name,
                    "clearance_id": file.clearance_id,
                    "reference_to_file": file.reference_to_file,
                    "expire_at": file.expire_at.isoformat(),
                    "user_id": file.user_id,
                    "is_private": file.is_private,
                    "symetric_key_encrypted": file.symetric_key_encrypted,
                    "tag_bytes": file.tag_bytes,
                    "iv_bytes": file.iv_bytes
                }, file.uid
                
            except Exception as e:
                print("rollback inicio")
                session.rollback()
                print("rollback fim")
                if file_url.exists():
                    file_url.unlink()
                raise e
        
        clearance_order = {
            "UNCLASSIFIED": 1,
            "CONFIDENTIAL": 2,
            "SECRET": 3,
            "TOP_SECRET": 4
        }

        user_clearance_level =session.exec(select(Clearance.name).where(Clearance.id == user_clearance.clearance_id)).first()  
        print(f"DEBUG: user_clearance={clearance_order[user_clearance_level]}, file_clearance={clearance_order[clearance_level]}")

        if clearance_order[user_clearance_level] > clearance_order[clearance_level]:
            self._create_log_entry(
                        session=session,
                        action="UPLOAD_DENIED",
                        description=f"User {user_id} tried to upload file {file_name} at {clearance_level} but has {user_clearance_level} clearance (no write-down)",
                        user_id=user_id
                    )
            print(f"DEBUG: Bell-LaPadula WRITE-DOWN DENIED: user={user_clearance_level}, file={clearance_level}", flush=True)
            return 

        created_at = datetime.now(timezone.utc)
        # will expired 3 days after the submition time
        expired_at=created_at + timedelta(days=3)
    
        
        file_url = self.UPLOAD_DIR / f"{uuid.uuid4()}.enc"
        
        file = File(
                file_name=file_name,
                clearance_id=clearance_id,
                reference_to_file=str(file_url),
                expire_at=expired_at,
                user_id=user_id,
                is_private=is_privat,

                symetric_key_encrypted=base64.b64encode(encrypted_key_bytes).decode() if encrypted_key_bytes else None,
                tag_bytes=tag_bytes,
                iv_bytes=iv_bytes,
                reason=reason if reason else None  # Store reason if provided
            )

        try:
            with open(file_url, "wb") as f:
                f.write(file_data)
            session.add(file)
            session.commit()
            session.refresh(file)
            file_to_return=file

            self._create_log_entry(
                session=session,
                action="UPLOAD",
                description=f"User {user_id} upload file{file_name} to {file_url} ",
                user_id=user_id
                )
            for dep in department_list:
                
                self._create_log_entry(
                session=session,
                action="UPLOAD",
                description=f"User {user_id} upload file{file_name} to {file_url} creating association betwern dep:{dep}",
                user_id=user_id
                )
                file_dep = FileDepartment(file_uid=file.uid,department_id=dep)
                session.add(file_dep)
            session.commit()

            return {
                "uid": file.uid,
                "file_name": file.file_name,
                "clearance_id": file.clearance_id,
                "reference_to_file": file.reference_to_file,
                "expire_at": file.expire_at.isoformat(),
                "user_id": file.user_id,
                "is_private": file.is_private,
                "symetric_key_encrypted": file.symetric_key_encrypted,
                "tag_bytes": file.tag_bytes,
                "iv_bytes": file.iv_bytes
            }   ,file_to_return.uid
        except Exception as e:
            print("rollback inicio")
            session.rollback()
            print("rollback fim")

            # if error remove the file 
            if file_url.exists():
                file_url.unlink()
            
            raise e
        
    
    def get_file(
        self,
        *,
        session: Session,

        user_id: int,

    ):

        self._create_log_entry(
                session=session,
                action="GET_FILE",
                description=f"User {user_id} acess his uploads list ,)",
                user_id=user_id
            )

        # Get files owned by the user
        owned_files = session.exec(select(File).where(File.user_id==user_id)).all()
        
        # Get files shared with the user
        shared_file_uids = session.exec(
            select(EncryptedFileKeys.file_uid).where(EncryptedFileKeys.recipient_user_id == user_id)
        ).all()
        
        shared_files = []
        if shared_file_uids:
            shared_files = session.exec(
                select(File).where(File.uid.in_(shared_file_uids))
            ).all()
        
        # Combine owned and shared files, avoiding duplicates
        owned_uids = {f.uid for f in owned_files}
        all_files = list(owned_files)
        for f in shared_files:
            if f.uid not in owned_uids:
                all_files.append(f)
        
        return all_files
    

    def get_one_file(
        self,
        *,
        session: Session,
        file_uid: str,
        user_id: int,

    ):
        file =session.exec(select(File).where(and_(
            File.uid==file_uid,File.user_id==user_id))).first()
        if file:
            self._create_log_entry(
                    session=session,
                    action="GET_FILE_SUCESS",
                    description=f"User  {user_id} owns the file retriving )",
                    user_id=user_id
                )
            return {
                "uid": file.uid,
                "file_name": file.file_name,
                "clearance_id": file.clearance_id,
                "reference_to_file": file.reference_to_file,
                "expire_at": file.expire_at.isoformat(),
                "user_id": file.user_id,
                "is_private": file.is_private,
                "symetric_key_encrypted": file.symetric_key_encrypted,
                "tag_bytes": file.tag_bytes,
                "iv_bytes": file.iv_bytes,
                "departments": session.exec(select(FileDepartment.department_id).where(FileDepartment.file_uid == file_uid)).all(),
                "clearance_name": session.exec(select(Clearance.name).where(Clearance.id == file.clearance_id)).first()
            }
             
        file =session.exec(select(File).where(and_(
            File.uid==file_uid))).first()
        if  not file:
            self._create_log_entry(
                    session=session,
                    action="GET_FILE_FAIL",
                    description=f"User {user_id} try to acess the file {file_uid} but it doenst exist )",
                    user_id=user_id
                )
            return 
        shared_file_uids = session.exec(
            select(EncryptedFileKeys).where(and_(EncryptedFileKeys.recipient_user_id == user_id,EncryptedFileKeys.file_uid==file_uid))
        ).first()
        if not shared_file_uids:
            self._create_log_entry(
                    session=session,
                    action="GET_FILE_FAIL",
                    description=f"User {user_id} try to acess the file {file_uid} but you dont have acess to it )",
                    user_id=user_id
                )
            return 
        
        self._create_log_entry(
                    session=session,
                    action="GET_FILE",
                    description=f"User {user_id} acess the file {file_uid},)",
                    user_id=user_id
                )

        return {
                "uid": file.uid,
                "file_name": file.file_name,
                "clearance_id": file.clearance_id,
                "reference_to_file": file.reference_to_file,
                "expire_at": file.expire_at.isoformat(),
                "user_id": file.user_id,
                "is_private": file.is_private,
                "symetric_key_encrypted": shared_file_uids.encrypted_key,
                "tag_bytes": file.tag_bytes,
                "iv_bytes": file.iv_bytes,
                "departments": session.exec(select(FileDepartment.department_id).where(FileDepartment.file_uid == file_uid)).all(),
                "clearance_name": session.exec(select(Clearance.name).where(Clearance.id == file.clearance_id)).first()
            }
    

    def download_file(self,        
        session: Session,
        file_uid: str,
        user_id: int,
        user_clearance : ClearanceTokens,
        reason: str):
        file =session.exec(select(File).where(and_(
            File.user_id==user_id,
            File.uid==file_uid))).first()
        #my file
        if file and file.is_private:
            self._create_log_entry(
                session=session,
                action="DOWNLOAD_SUCEESS",
                description=f"User {user_id} dowload is own file {file_uid}",
                user_id=user_id
            )
            return file.file_name,file.reference_to_file,file.symetric_key_encrypted,file.iv_bytes,file.tag_bytes

        file =session.exec(select(File).where(
            File.uid==file_uid  )).first()
        if not file:
            self._create_log_entry(
                    session=session,
                    action="DOWNLOAD_FAILED",
                    description=f"User {user_id} tried to dowload non-existent file {file_uid}",
                    user_id=user_id
                )
            return
            
        if file.is_private:
            shared = session.exec(select(EncryptedFileKeys).where(and_(
                    EncryptedFileKeys.recipient_user_id==user_id,
                    EncryptedFileKeys.file_uid==file_uid  ))).first()  
            if not shared:
                self._create_log_entry(
                    session=session,
                    action="DOWNLOAD_FAILED",
                    description=f"User {user_id} tried to dowload  file {file_uid} you dont own doesnt have bein shared with you",
                    user_id=user_id
                )
                return
                
        clearance_order = {
            "UNCLASSIFIED": 1,
            "CONFIDENTIAL": 2,
            "SECRET": 3,
            "TOP_SECRET": 4
        }

        clearance_file = session.exec(select(Clearance.name).where(Clearance.id==file.clearance_id)).first()

        deps=session.exec(select(FileDepartment.department_id).where(FileDepartment.file_uid==file_uid)).all()

        trusted_officer = session.exec(select(Role).where(Role.role == RoleType.TRUSTED_OFFICER)).first()
        deps_trusted = session.exec(select(RoleToken.department_id).where(and_(RoleToken.user_id == user_id, RoleToken.role_id == trusted_officer.id))).all()

        if reason and not file.is_private and all(dp in deps_trusted for dp in deps):
            self._create_log_entry(
                session=session,
                action="SECURITY_OFFICER_BYPASS_DOWNLOAD",
                description=f"Security Officer {user_id} uploaded file {file.file_name} to {deps} bypassing MLS. Reason: {reason}",
                user_id=user_id
            )
            return file.file_name,file.reference_to_file,shared.encrypted_key if file.is_private else None,file.iv_bytes,file.tag_bytes


        if not user_clearance:
            self._create_log_entry(
                session=session,
                action="MLS_VIOLATION",
                description=f"User {user_id} has no active clearance token",
                user_id=user_id
            
            )
            return 
        
        clearance_deps = session.exec(select(ClearanceDepartment.department_id).where(ClearanceDepartment.clearance_token_id==user_clearance.id)).all()

        for dep in deps:
            
            if dep not in clearance_deps:
                self._create_log_entry(
                    session=session,
                    action="MLS_VIOLATION",
                    description=f"User {user_id} doesnt have clearance on the dep {dep.department_id} which file {file_uid} belongs",
                    user_id=user_id
                )
                return 


        clearance_level = session.exec(
            select(Clearance.name).where(Clearance.id == user_clearance.clearance_id)
        ).first()

        
        if clearance_order[clearance_level]<clearance_order[clearance_file]:
            self._create_log_entry(
                session=session,
                action="MLS_VIOLATION",
                description=f"User {user_id} clearance too low for file {file_uid}",
                user_id=user_id
            )
            return 

        self._create_log_entry(
                session=session,
                action="DOWNLOAD_SUCEESS",
                description=f"User {user_id} dowload a file that was shered with him {file_uid}",
                user_id=user_id
            )

        return file.file_name,file.reference_to_file,shared.encrypted_key if file.is_private else None,file.iv_bytes,file.tag_bytes
        

        


    def delete_file( self,
        *,
        session: Session,
        transfer_uid: str,
        user_id: int,):

        file = session.exec(select(File).where(File.uid==transfer_uid)).first()
        if not file:
            self._create_log_entry(
                session=session,
                action="FILE_DELETE_FAILED",
                description=f"User {user_id} tried to delete non-existent file {transfer_uid}",
                user_id=user_id
            )
            return 
        if(file.user_id!=user_id):
            self._create_log_entry(
                session=session,
                action="FILE_DELETE_DENIED",
                description=f"User {user_id} denied access to delete file {transfer_uid} (owner: {file.user_id})",
                user_id=user_id
            )
            return 
        
        session.delete(file)  
        session.commit()

        # removes from file system
        file_path = Path(file.reference_to_file)
        if file_path.exists():
            file_path.unlink()

        self._create_log_entry(
            session=session,
            action="FILE_DELETED",
            description=f"User {user_id} successfully deleted file {transfer_uid} ({file.file_name})",
            user_id=user_id
        )
        return file

    def share_file(  self,      
            session: Session,
        file_uid: str,
        owner_id: int,
        user_share_id:int,
        encrypted_key_bytes:bytes):

        file = session.exec(select(File).where(and_(File.uid==file_uid,File.user_id==owner_id))).first()
        if not file:
            self._create_log_entry(
                session=session,
                action="FILE_SHARED_FAILED",
                description=f"User {owner_id} tried to shared non-existent or he doesnt own that file {file_uid}",
                user_id=owner_id
            )
            return 
        try:
            entry = EncryptedFileKeys(
                recipient_user_id=user_share_id,
                file_uid=file.uid,
                encrypted_key=base64.b64encode(encrypted_key_bytes).decode()
            )
            session.add(entry)
            session.commit()
            session.refresh(entry)
            self._create_log_entry(
                session=session,
                action="FILE_SHARED",
                description=f"User {owner_id} shared {file_uid} with {user_share_id}",
                user_id=owner_id
            )
            return entry
        except Exception as e:
            print("rollback inicio")
            session.rollback()
            raise e
