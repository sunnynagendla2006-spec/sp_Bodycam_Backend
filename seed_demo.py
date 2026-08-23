from app.database import SessionLocal
from app.models import User, UserRole, UserStatus
from app.auth.security import hash_password

def seed():
    db = SessionLocal()
    users = [
        {"phone": "9990001001", "role": UserRole.admin},
        {"phone": "9990001002", "role": UserRole.control_room},
        {"phone": "9990001003", "role": UserRole.station},
        {"phone": "9990001004", "role": UserRole.constable},
        {"phone": "9990001005", "role": UserRole.citizen},
    ]
    
    hashed_pwd = hash_password("Demo@12345")
    
    for u in users:
        existing = db.query(User).filter(User.phone == u["phone"]).first()
        if not existing:
            user = User(
                phone=u["phone"],
                role=u["role"],
                status=UserStatus.active,
                hashed_password=hashed_pwd
            )
            db.add(user)
    
    db.commit()
    db.close()
    print("Demo users seeded successfully.")

if __name__ == "__main__":
    seed()
