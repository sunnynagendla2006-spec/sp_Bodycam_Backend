"""
TEST DATA ONLY -- never run this against a production database.

Creates 5 synthetic development/test constables, 5 synthetic test police
stations, and 5 synthetic test devices, for physical end-to-end validation
of the mobile app + backend + dashboard. All records are clearly marked as
test data (station names prefixed "Test ", badge numbers "Constable Test
0N", device identifiers "TEST-BODYCAM-00N", phone numbers in the 99900020xx
range -- deliberately a DIFFERENT range from seed_demo.py's 99900010xx
accounts, which already exist as one-of-each-role demo logins and must not
be overwritten or reinterpreted as constables here).

Station coordinates are synthetic, illustrative Hyderabad-area points
chosen only to exercise the map/location display paths with real-looking
numbers -- they do NOT correspond to any actual police station.

No battery/heartbeat/GPS-location rows are seeded here on purpose: those
must only ever come from a real device actually reporting them (that is
the entire point of the physical validation this data supports). Seeding
fake sensor readings would defeat that validation.

Idempotent: safe to run repeatedly. Existing rows (matched by phone /
station name / device_identifier) are left untouched, not duplicated.

Usage:
    python scripts/seed_test_data.py            # create/verify test data
    python scripts/seed_test_data.py --reset     # remove ONLY this test data
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database import SessionLocal
from app.models import User, UserRole, UserStatus, Constable, ConstableStatus, PoliceStation, Device, DeviceStatus
from app.auth.security import hash_password

TEST_PASSWORD = "Demo@12345"  # matches seed_demo.py's existing test-environment convention

STATIONS = [
    {"name": "Test Control Station", "longitude": 78.4500, "latitude": 17.4300},
    {"name": "Test North Station", "longitude": 78.4800, "latitude": 17.4700},
    {"name": "Test South Station", "longitude": 78.4700, "latitude": 17.3600},
    {"name": "Test East Station", "longitude": 78.5200, "latitude": 17.4200},
    {"name": "Test West Station", "longitude": 78.4000, "latitude": 17.4000},
]

CONSTABLES = [
    {"n": 1, "phone": "9990002001", "station": "Test Control Station"},
    {"n": 2, "phone": "9990002002", "station": "Test North Station"},
    {"n": 3, "phone": "9990002003", "station": "Test South Station"},
    {"n": 4, "phone": "9990002004", "station": "Test East Station"},
    {"n": 5, "phone": "9990002005", "station": "Test West Station"},
]

TEST_PHONE_PREFIX = "999000200"  # matches CONSTABLES above -- used by --reset to find exactly these rows
TEST_DEVICE_PREFIX = "TEST-BODYCAM-"
TEST_STATION_NAMES = [s["name"] for s in STATIONS]


def seed():
    db = SessionLocal()
    try:
        stations_by_name = {}
        for s in STATIONS:
            existing = db.query(PoliceStation).filter(PoliceStation.name == s["name"]).first()
            if existing:
                stations_by_name[s["name"]] = existing
                continue
            station = PoliceStation(
                name=s["name"],
                location=f"POINT({s['longitude']} {s['latitude']})",
                contact="000-0000",
            )
            db.add(station)
            db.flush()
            stations_by_name[s["name"]] = station
            print(f"created station: {s['name']} (SYNTHETIC TEST LOCATION {s['latitude']}, {s['longitude']})")

        hashed_pwd = hash_password(TEST_PASSWORD)
        for c in CONSTABLES:
            badge = f"Constable Test {c['n']:02d}"
            device_identifier = f"{TEST_DEVICE_PREFIX}{c['n']:03d}"
            station = stations_by_name[c["station"]]

            user = db.query(User).filter(User.phone == c["phone"]).first()
            if not user:
                user = User(phone=c["phone"], role=UserRole.constable, status=UserStatus.active, hashed_password=hashed_pwd)
                db.add(user)
                db.flush()
                print(f"created user: {c['phone']} (role=constable)")

            constable = db.query(Constable).filter(Constable.user_id == user.id).first()
            if not constable:
                constable = Constable(
                    user_id=user.id,
                    badge_number=badge,
                    station_id=station.id,
                    status=ConstableStatus.offline,
                )
                db.add(constable)
                db.flush()
                print(f"created constable: {badge} -> {c['station']}")
            elif constable.station_id != station.id:
                constable.station_id = station.id
                print(f"updated constable station: {badge} -> {c['station']}")

            device = db.query(Device).filter(Device.device_identifier == device_identifier).first()
            if not device:
                device = Device(
                    constable_id=constable.id,
                    device_identifier=device_identifier,
                    platform="android",
                    status=DeviceStatus.offline,
                )
                db.add(device)
                print(f"created device: {device_identifier} -> {badge}")
            elif device.constable_id != constable.id:
                device.constable_id = constable.id
                print(f"updated device association: {device_identifier} -> {badge}")

        db.commit()
        print(f"\nTest data seeded. Password for all 5 test constables: {TEST_PASSWORD}")
    finally:
        db.close()


def reset():
    """Deletes ONLY rows matching this script's own test markers -- never
    touches seed_demo.py's accounts or any other data."""
    db = SessionLocal()
    try:
        devices = db.query(Device).filter(Device.device_identifier.like(f"{TEST_DEVICE_PREFIX}%")).all()
        for d in devices:
            db.delete(d)
        print(f"removed {len(devices)} test device(s)")

        users = db.query(User).filter(User.phone.like(f"{TEST_PHONE_PREFIX}%")).all()
        for u in users:
            constable = db.query(Constable).filter(Constable.user_id == u.id).first()
            if constable:
                db.delete(constable)
            db.delete(u)
        print(f"removed {len(users)} test constable/user pair(s)")

        stations = db.query(PoliceStation).filter(PoliceStation.name.in_(TEST_STATION_NAMES)).all()
        for s in stations:
            db.delete(s)
        print(f"removed {len(stations)} test station(s)")

        db.commit()
        print("\nTest data reset complete.")
    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reset", action="store_true", help="remove the test data created by this script instead of creating it")
    args = parser.parse_args()
    reset() if args.reset else seed()
