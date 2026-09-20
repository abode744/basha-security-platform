import os
from pydantic_settings import BaseSettings, SettingsConfigDict

is_vercel = bool(os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))
default_db = "sqlite:////tmp/basha_local.db" if is_vercel else "sqlite:///./basha_local.db"
default_rep = "/tmp/reports" if is_vercel else "reports"

class Settings(BaseSettings):
    model_config=SettingsConfigDict(env_file='.env', extra='ignore')
    database_url:str=default_db
    redis_url:str='redis://redis:6379/0'
    basha_secret_key:str='b4eb051caf7549f0bb0261d23c901fe315f1007c260640488e5a7a9768bdc3e3'
    basha_admin_user:str='abod'
    basha_admin_password:str='2024'
    default_max_rps:float=1.0
    default_stage_cooldown_seconds:int=240
    report_dir:str=default_rep
    jwt_ttl_minutes:int=480

settings=Settings()
