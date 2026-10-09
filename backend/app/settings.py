import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    mongo_uri: str
    redis_url: str
    blob_root: str
    work_root: str
    scanner_mode: str
    jwt_secret: str
    jwt_expire_hours: int
    ldap_server: str
    ldap_bind_username: str
    ldap_bind_password: str
    ldap_account_base: str
    ldap_account_pattern: str
    ldap_account_ssh_username: str
    auth_admin_users: str
    auth_default_role: str
    app_config_file: str

    @staticmethod
    def from_env() -> "Settings":
        return Settings(
            mongo_uri=os.getenv("MONGO_URI", "mongodb://localhost:27017/supplychain"),
            redis_url=os.getenv("REDIS_URL", "redis://localhost:6379/8"),
            blob_root=os.getenv("BLOB_ROOT", "/opt/openMastiff/data/blobs"),
            work_root=os.getenv("WORK_ROOT", "/opt/openMastiff/data/work"),
            scanner_mode=os.getenv("SCANNER_MODE", "local"),
            jwt_secret=os.getenv("JWT_SECRET", "openmastiff-dev-secret"),
            jwt_expire_hours=int(os.getenv("JWT_EXPIRE_HOURS", "8")),
            ldap_server=os.getenv("LDAP_SERVER", "ldap://ldap.example.com:389"),
            ldap_bind_username=os.getenv("LDAP_BIND_USERNAME", "cn=readonly,dc=example,dc=com"),
            ldap_bind_password=os.getenv("LDAP_BIND_PASSWORD", ""),
            ldap_account_base=os.getenv("LDAP_ACCOUNT_BASE", "ou=people,dc=example,dc=com"),
            ldap_account_pattern=os.getenv(
                "LDAP_ACCOUNT_PATTERN",
                "(&(objectClass=inetOrgPerson)(uid=${username}))",
            ),
            ldap_account_ssh_username=os.getenv("LDAP_ACCOUNT_SSH_USERNAME", "uid"),
            auth_admin_users=os.getenv("AUTH_ADMIN_USERS", ""),
            auth_default_role=os.getenv("AUTH_DEFAULT_ROLE", "viewer"),
            app_config_file=os.getenv("APP_CONFIG_FILE", "/opt/openMastiff/config/app_config.json"),
        )


settings = Settings.from_env()

