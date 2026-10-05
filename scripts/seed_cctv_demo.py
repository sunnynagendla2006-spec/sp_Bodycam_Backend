"""
DEMO DATA ONLY -- never run this against a production database.

Seeds a handful of clearly-marked demo CCTVCamera rows so the /cctv/*
endpoints have something to list/test/search in a dev environment. Every
camera points at 127.0.0.1 on a harmless, almost-certainly-unused port --
these are NOT expected to actually answer an RTSP probe (status will show
`offline` until a real RTSP source is pointed at one of these ports), and
are marked `is_demo=True` and named accordingly so nobody mistakes one
for a real camera.

Requires CCTV_ALLOWED_NETWORKS to include 127.0.0.1/32 (see .env.example)
-- this script sets it itself via os.environ if unset, same convention as
tests/conftest.py.

Idempotent: safe to run repeatedly, matched by camera_code.

Usage:
    python scripts/seed_cctv_demo.py
    python scripts/seed_cctv_demo.py --reset
"""
import argparse
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("CCTV_ALLOWED_NETWORKS", "127.0.0.1/32")

from app.database import init_db
from app.geo import point
from app.models import CCTVCamera

CAMERAS = [
    {"code": "CAM-DEMO-01", "name": "Demo Camera -- Main Gate", "zone": "MAIN_GATE", "port": 55401, "longitude": 78.4500, "latitude": 17.4300},
    {"code": "CAM-DEMO-02", "name": "Demo Camera -- Temple Area", "zone": "TEMPLE_AREA", "port": 55402, "longitude": 78.4550, "latitude": 17.4330},
    {"code": "CAM-DEMO-03", "name": "Demo Camera -- Parking Area", "zone": "PARKING_AREA", "port": 55403, "longitude": 78.4480, "latitude": 17.4360},
]


async def seed():
    await init_db()
    for c in CAMERAS:
        existing = await CCTVCamera.find_one(CCTVCamera.camera_code == c["code"])
        if existing:
            continue
        camera = CCTVCamera(
            name=c["name"],
            camera_code=c["code"],
            zone=c["zone"],
            location=point(c["longitude"], c["latitude"]),
            stream_host="127.0.0.1",
            stream_port=c["port"],
            is_demo=True,
        )
        await camera.insert()
        print(f"created camera: {c['code']} ({c['name']})")
    print("\nDemo CCTV cameras seeded. Status will show 'offline' until a real RTSP source answers on the configured port.")


async def reset():
    await init_db()
    cameras = await CCTVCamera.find({"camera_code": {"$in": [c["code"] for c in CAMERAS]}}).to_list()
    for cam in cameras:
        await cam.delete()
    print(f"removed {len(cameras)} demo camera(s)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reset", action="store_true")
    args = parser.parse_args()
    asyncio.run(reset() if args.reset else seed())
