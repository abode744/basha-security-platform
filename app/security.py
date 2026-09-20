from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
import bcrypt
from .config import settings

def hash_password(p: str) -> str:
    pwd_bytes = p.encode('utf-8')[:72]
    return bcrypt.hashpw(pwd_bytes, bcrypt.gensalt()).decode('utf-8')

def verify_password(p: str, h: str) -> bool:
    try:
        pwd_bytes = p.encode('utf-8')[:72]
        return bcrypt.checkpw(pwd_bytes, h.encode('utf-8'))
    except Exception:
        return False

def make_token(u: str) -> str:
    return jwt.encode(
        {'sub': u, 'exp': datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_ttl_minutes)},
        settings.basha_secret_key,
        algorithm='HS256'
    )

def decode_token(v: str):
    try:
        return jwt.decode(v, settings.basha_secret_key, algorithms=['HS256'])
    except JWTError:
        return None
