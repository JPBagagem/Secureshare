from sqlmodel import Session, select,and_
import hashlib
from datetime import  datetime,timezone
from src.models.Department import Department,DepartmentCreate
from src.models.RoleToken import RoleToken
from src.models.Logs import Logs
from src.models.Role import Role, RoleType

class DepartmentService:


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


    def check_if_admin(self,session: Session,
        user_id: int,)->bool:
        tokens = session.exec(select(RoleToken).join(Role,RoleToken.role_id==Role.id)
                              .where(
                                  and_(
                                    user_id==RoleToken.user_id,
                                    Role.role==RoleType.ADMINISTRATOR))).first()
        
        return tokens is not None


    def get_departments(
        self,
        *,
        session: Session,

        user_id: int,

    ):
        if( not self.check_if_admin(session=session,user_id=user_id)):
            self._create_log_entry(
                session=session,
                action="CHECK_ADMIN_FAIL",
                description=f"User {user_id} doesnt have a admin role active",
                user_id=user_id
            )
            return
        self._create_log_entry(
                session=session,
                action="DEPARTMENTS_ACCESSED",
                description=f"User {user_id} has a admin role active",
                user_id=user_id
            )
      
        deps = session.exec(select(Department)).all()
        return deps


    #
    def delet_departments(
        self,
        *,
        session: Session,
        dep_id:int,
        user_id: int,

    ):
        if( not self.check_if_admin(session=session,user_id=user_id)):
            self._create_log_entry(
                session=session,
                action="CHECK_ADMIN_FAIL",
                description=f"User {user_id} doesnt have a admin role active",
                user_id=user_id
            )
            return
        dep = session.exec(select(Department).where(Department.id==dep_id)).first()
        if not dep:

            self._create_log_entry(
                    session=session,
                    action="DEPARTMENT_UNKNOWN",
                    description=f"User {user_id} try to delete dep {dep_id} but it was not found",
                    user_id=user_id
                )
            return 
        session.delete(dep)
        session.commit()
        self._create_log_entry(
                    session=session,
                    action="DEPARTMENT_DELETED",
                    description=f"User {user_id} delete dep {dep_id}",
                    user_id=user_id
                )

        return dep

    def add_department(
        self,
        *,
        session: Session,
        data:DepartmentCreate,
        user_id: int,

    ):
        if( not self.check_if_admin(session=session,user_id=user_id)):
            self._create_log_entry(
                session=session,
                action="CHECK_ADMIN_FAIL",
                description=f"User {user_id} doesnt have a admin role active",
                user_id=user_id
            )
            return
        
        existing = session.exec(
            select(Department).where(Department.name == data.name)
            ).first()
    
        if existing:
            self._create_log_entry(
                session=session,
                action="DEPARTMENT_DUPLICATE",
                description=f"Admin {user_id} tried to create duplicate department '{data.name}'",
                user_id=user_id
            )
            return None
        
        department = Department(
            name=data.name,
            created_at=datetime.now(timezone.utc),
            created_by=user_id
        )
        
        session.add(department)
        session.commit()
        session.refresh(department)

        self._create_log_entry(
                        session=session,
                        action="DEPARTMENT_CREATED",
                        description=f"User {user_id} created dep {department.id}",
                        user_id=user_id
        )
        return department
    