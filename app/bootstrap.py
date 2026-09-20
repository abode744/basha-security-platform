from .db import Base, engine, SessionLocal
from .models import User
from .security import hash_password
from .config import settings

Base.metadata.create_all(engine)
db = SessionLocal()
u = db.execute(__import__('sqlalchemy').select(User).where(User.username == settings.basha_admin_user)).scalar_one_or_none()
if not u:
    db.add(User(username=settings.basha_admin_user, password_hash=hash_password(settings.basha_admin_password), role='admin'))
    db.commit()
    print(f'Admin user "{settings.basha_admin_user}" created successfully')
else:
    u.password_hash = hash_password(settings.basha_admin_password)
    u.disabled = False
    db.commit()
    print(f'Admin user "{settings.basha_admin_user}" credentials updated successfully')
db.close()
