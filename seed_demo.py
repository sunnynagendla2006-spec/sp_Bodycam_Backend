import asyncio

from app.database import init_db
from app.models import User, UserRole, UserStatus
from app.auth.security import hash_password


async def seed():
    await init_db()

    users = [
        {"phone": "9990001001", "role": UserRole.admin},
        {"phone": "9990001002", "role": UserRole.control_room},
        {"phone": "9990001003", "role": UserRole.station},
        {"phone": "9990001004", "role": UserRole.constable},
        {"phone": "9990001005", "role": UserRole.citizen},
    ]

    hashed_pwd = hash_password("Demo@12345")

    for u in users:
        existing = await User.find_one(User.phone == u["phone"])
        if not existing:
            user = User(
                phone=u["phone"],
                role=u["role"],
                status=UserStatus.active,
                hashed_password=hashed_pwd,
            )
            await user.insert()

    print("Demo users seeded successfully.")


if __name__ == "__main__":
    asyncio.run(seed())
