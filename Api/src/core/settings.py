from pydantic import  computed_field
from pydantic_settings import SettingsConfigDict,BaseSettings

from src.core.generate_keys import load_or_generate_server_keys
from cryptography.hazmat.primitives import serialization

class Settings(BaseSettings):

    model_config = SettingsConfigDict(
        env_file=".env",
        env_ignore_empty=True,
        extra="ignore",
    )

    SQLITE_FILE_PATH: str = "database.db"
    
    PRIVATE_KEY: str | None = None
    PUBLIC_KEY: str | None = None

    def model_post_init(self, __context):
        _private_key_obj, _public_key_obj = load_or_generate_server_keys()
        
        self.PRIVATE_KEY = _private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        self.PUBLIC_KEY = _public_key_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    @computed_field
    @property
    def DATABASE_URI(self) -> str:
        return f"sqlite:///{self.SQLITE_FILE_PATH}"
  
settings = Settings()