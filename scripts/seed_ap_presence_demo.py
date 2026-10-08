"""
DEMO DATA ONLY -- never run this against a production database.

Seeds the "JATARA-DEMO-001" deployment for the AP-based presence feature
(including virtual AP mode): a Deployment row, 4 demo AccessPoints
(AP-01..AP-04, one per zone ZONE-01..ZONE-04), and three demo
constables/devices (POL-023/DEV-023, POL-024/DEV-024, POL-025/DEV-025),
so the presence/virtual-AP/zone APIs
(app/routers/presence.py, app/routers/access_points.py,
app/routers/deployments.py) can be exercised end-to-end without
physically deploying Wi-Fi access points.

Every row created here is explicitly marked as demo data:
  - Deployment.is_demo = True, AccessPoint.is_demo = True
  - the constables' phone numbers are in a distinct, clearly-synthetic
    range (999000302x) from both seed_demo.py's one-per-role accounts
    (99900010xx) and seed_test_data.py's physical-validation constables
    (999000200x), so none of the three seed scripts can ever collide or
    overwrite each other's rows.

Coordinates are synthetic, illustrative points within one small area --
they do NOT correspond to any real physical deployment.

Idempotent: safe to run repeatedly. Existing rows (matched by
AccessPoint.code / User.phone / Device.device_identifier /
Deployment.name) are reconciled (zone/name/location updated if this
script's own definitions changed) rather than duplicated.

Usage:
    python scripts/seed_ap_presence_demo.py            # create/verify demo data
    python scripts/seed_ap_presence_demo.py --reset     # remove ONLY this demo data
"""
import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database import init_db
from app.models import (
    AccessPoint,
    Constable,
    ConstableStatus,
    Deployment,
    DeploymentStatus,
    Device,
    DeviceStatus,
    User,
    UserRole,
    UserStatus,
)
from app.auth.security import hash_password

DEPLOYMENT_NAME = "JATARA-DEMO-001"
TEST_PASSWORD = "Demo@12345"  # matches seed_demo.py/seed_test_data.py's existing convention

OFFICERS = [
    {"phone": "9990003023", "badge": "POL-023", "device": "DEV-023"},
    {"phone": "9990003024", "badge": "POL-024", "device": "DEV-024"},
    {"phone": "9990003025", "badge": "POL-025", "device": "DEV-025"},
]

ACCESS_POINTS = [
    {"code": "AP-01", "name": "Main Gate", "zone": "ZONE-01", "longitude": 78.4500, "latitude": 17.4300},
    {"code": "AP-02", "name": "Main Temple", "zone": "ZONE-02", "longitude": 78.4550, "latitude": 17.4330},
    {"code": "AP-03", "name": "Parking Area", "zone": "ZONE-03", "longitude": 78.4480, "latitude": 17.4360},
    {"code": "AP-04", "name": "Food / Market Area", "zone": "ZONE-04", "longitude": 78.4530, "latitude": 17.4345},
]


async def seed():
    from app.geo import point

    await init_db()

    deployment = await Deployment.find_one(Deployment.name == DEPLOYMENT_NAME)
    if not deployment:
        deployment = Deployment(name=DEPLOYMENT_NAME, status=DeploymentStatus.active, is_demo=True)
        await deployment.insert()
        print(f"created deployment: {DEPLOYMENT_NAME}")

    for ap_def in ACCESS_POINTS:
        existing = await AccessPoint.find_one(AccessPoint.code == ap_def["code"])
        new_location = point(ap_def["longitude"], ap_def["latitude"])
        if not existing:
            ap = AccessPoint(
                code=ap_def["code"], name=ap_def["name"], zone=ap_def["zone"],
                deployment=DEPLOYMENT_NAME, location=new_location, is_demo=True,
            )
            await ap.insert()
            print(f"created access point: {ap_def['code']} ({ap_def['name']}) -- {ap_def['zone']} -- {DEPLOYMENT_NAME}")
        elif existing.zone != ap_def["zone"] or existing.name != ap_def["name"] or existing.deployment != DEPLOYMENT_NAME:
            existing.zone = ap_def["zone"]
            existing.name = ap_def["name"]
            existing.deployment = DEPLOYMENT_NAME
            existing.location = new_location
            await existing.save()
            print(f"updated access point: {ap_def['code']} -> {ap_def['zone']} ({ap_def['name']})")

    hashed_pwd = hash_password(TEST_PASSWORD)
    for officer in OFFICERS:
        user = await User.find_one(User.phone == officer["phone"])
        if not user:
            user = User(phone=officer["phone"], role=UserRole.constable, status=UserStatus.active, hashed_password=hashed_pwd)
            await user.insert()
            print(f"created user: {officer['phone']} (role=constable)")

        constable = await Constable.find_one(Constable.user_id == user.id)
        if not constable:
            constable = Constable(user_id=user.id, badge_number=officer["badge"], status=ConstableStatus.available)
            await constable.insert()
            print(f"created constable: {officer['badge']}")

        device = await Device.find_one(Device.device_identifier == officer["device"])
        if not device:
            device = Device(
                constable_id=constable.id, device_identifier=officer["device"],
                platform="android", status=DeviceStatus.offline,
            )
            await device.insert()
            print(f"created device: {officer['device']} -> {officer['badge']}")
        elif device.constable_id != constable.id:
            device.constable_id = constable.id
            await device.save()
            print(f"updated device association: {officer['device']} -> {officer['badge']}")

    print(f"\n{DEPLOYMENT_NAME} demo data seeded.")
    print(f"Login: phone={OFFICERS[0]['phone']} password={TEST_PASSWORD} (and the other two officer phones, same password)")
    print("Officers: " + ", ".join(f"{o['badge']}/{o['device']}" for o in OFFICERS))
    print("Access points: " + ", ".join(f"{a['code']} ({a['zone']})" for a in ACCESS_POINTS))


async def reset():
    """Deletes ONLY rows matching this script's own markers -- never touches seed_demo.py's or seed_test_data.py's rows."""
    await init_db()

    deployment = await Deployment.find_one(Deployment.name == DEPLOYMENT_NAME)
    if deployment:
        await deployment.delete()
        print(f"removed deployment: {DEPLOYMENT_NAME}")

    aps = await AccessPoint.find(AccessPoint.deployment == DEPLOYMENT_NAME).to_list()
    for ap in aps:
        await ap.delete()
    print(f"removed {len(aps)} demo access point(s)")

    for officer in OFFICERS:
        device = await Device.find_one(Device.device_identifier == officer["device"])
        if device:
            await device.delete()
            print(f"removed demo device: {officer['device']}")

        user = await User.find_one(User.phone == officer["phone"])
        if user:
            constable = await Constable.find_one(Constable.user_id == user.id)
            if constable:
                await constable.delete()
            await user.delete()
            print(f"removed demo constable/user: {officer['badge']}")

    print(f"\n{DEPLOYMENT_NAME} demo data reset complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reset", action="store_true", help="remove the demo data created by this script instead of creating it")
    args = parser.parse_args()
    asyncio.run(reset() if args.reset else seed())
