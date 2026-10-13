"""Geographic Event Zones CRUD, validation, and location update integration tests."""
import pytest
from app import models

pytestmark = pytest.mark.usefixtures("mongo_db")


def sample_zone_payload():
    return {
        "code": "ZONE-MAIN-GATE",
        "name": "Main Gate & Security Check",
        "description": "Primary entrance corridor",
        "deployment": "JATARA-DEMO-001",
        "zone_type": "MAIN_GATE",
        "coordinates": [
            [
                [80.6000, 16.5000],
                [80.6100, 16.5000],
                [80.6100, 16.5100],
                [80.6000, 16.5100],
                [80.6000, 16.5000],
            ]
        ],
        "priority": 10,
        "color": "#10B981",
        "enabled": True,
    }


async def test_admin_can_create_and_read_event_zone(full_client, make_user, auth_header):
    await make_user(phone="zone_admin_1", password="pw", role="admin")
    headers = await auth_header("zone_admin_1", "pw")

    # Create zone
    res = await full_client.post("/event-zones/", json=sample_zone_payload(), headers=headers)
    assert res.status_code == 201, res.text
    data = res.json()
    assert data["code"] == "ZONE-MAIN-GATE"
    assert data["name"] == "Main Gate & Security Check"
    assert data["enabled"] is True
    zone_id = data["id"]

    # List zones
    list_res = await full_client.get("/event-zones/", headers=headers)
    assert list_res.status_code == 200
    items = list_res.json()
    assert any(item["id"] == zone_id for item in items)

    # Get by id
    get_res = await full_client.get(f"/event-zones/{zone_id}", headers=headers)
    assert get_res.status_code == 200
    assert get_res.json()["code"] == "ZONE-MAIN-GATE"


@pytest.mark.parametrize("role", ["control_room", "station", "constable", "citizen"])
async def test_non_admin_cannot_create_event_zone(full_client, make_user, auth_header, role):
    await make_user(phone=f"zone_user_{role}", password="pw", role=role)
    headers = await auth_header(f"zone_user_{role}", "pw")

    res = await full_client.post("/event-zones/", json=sample_zone_payload(), headers=headers)
    assert res.status_code == 403


async def test_invalid_geojson_polygons_rejected(full_client, make_user, auth_header):
    await make_user(phone="zone_admin_inv", password="pw", role="admin")
    headers = await auth_header("zone_admin_inv", "pw")

    # 1. Unclosed ring (first != last)
    unclosed = {
        "code": "ZONE-UNCLOSED",
        "name": "Unclosed Zone",
        "coordinates": [
            [
                [80.6000, 16.5000],
                [80.6100, 16.5000],
                [80.6100, 16.5100],
                [80.6000, 16.5150],  # not closed
            ]
        ],
    }
    res1 = await full_client.post("/event-zones/", json=unclosed, headers=headers)
    assert res1.status_code == 400
    assert "not closed" in res1.text

    # 2. Coordinates out of range (latitude > 90)
    invalid_lat = {
        "code": "ZONE-BAD-LAT",
        "name": "Bad Latitude",
        "coordinates": [
            [
                [80.6000, 16.5000],
                [80.6100, 95.0000],
                [80.6100, 16.5100],
                [80.6000, 16.5000],
            ]
        ],
    }
    res2 = await full_client.post("/event-zones/", json=invalid_lat, headers=headers)
    assert res2.status_code == 400

    # 3. Degenerate ring (< 4 coordinates)
    too_few = {
        "code": "ZONE-FEW",
        "name": "Too few points",
        "coordinates": [
            [
                [80.6000, 16.5000],
                [80.6100, 16.5000],
                [80.6000, 16.5000],
            ]
        ],
    }
    res3 = await full_client.post("/event-zones/", json=too_few, headers=headers)
    assert res3.status_code == 400


async def test_admin_can_update_and_disable_zone(full_client, make_user, auth_header):
    await make_user(phone="zone_admin_upd", password="pw", role="admin")
    headers = await auth_header("zone_admin_upd", "pw")

    res = await full_client.post("/event-zones/", json=sample_zone_payload(), headers=headers)
    assert res.status_code == 201
    zone_id = res.json()["id"]

    # Update metadata & priority
    patch_res = await full_client.patch(
        f"/event-zones/{zone_id}",
        json={"priority": 25, "name": "Updated Main Gate"},
        headers=headers,
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["priority"] == 25
    assert patch_res.json()["name"] == "Updated Main Gate"

    # Disable zone
    disable_res = await full_client.post(f"/event-zones/{zone_id}/disable", headers=headers)
    assert disable_res.status_code == 200
    assert disable_res.json()["enabled"] is False

    # Filter by enabled=True excludes it
    list_active = await full_client.get("/event-zones/?enabled=true", headers=headers)
    assert not any(z["id"] == zone_id for z in list_active.json())


async def test_constable_location_update_detects_geographic_zone_and_transitions(
    full_client, make_user, auth_header, make_constable
):
    await make_user(phone="zone_admin_tr", password="pw", role="admin")
    admin_headers = await auth_header("zone_admin_tr", "pw")

    # Create Main Gate zone: [80.6000, 16.5000] to [80.6100, 16.5100]
    await full_client.post("/event-zones/", json=sample_zone_payload(), headers=admin_headers)

    # Create Temple zone: [80.6200, 16.5000] to [80.6300, 16.5100]
    temple_zone = {
        "code": "ZONE-TEMPLE",
        "name": "Temple Sanctum",
        "deployment": "JATARA-DEMO-001",
        "zone_type": "TEMPLE",
        "coordinates": [
            [
                [80.6200, 16.5000],
                [80.6300, 16.5000],
                [80.6300, 16.5100],
                [80.6200, 16.5100],
                [80.6200, 16.5000],
            ]
        ],
        "priority": 5,
        "enabled": True,
    }
    await full_client.post("/event-zones/", json=temple_zone, headers=admin_headers)

    # Create Constable user + profile via fixture
    constable_user, constable = await make_constable(phone="9999000001", password="pw", badge_number="AP-CONST-TR")
    constable_headers = await auth_header("9999000001", "pw")

    # Step 1: Send fix INSIDE Main Gate: [80.6050, 16.5050]
    loc1 = await full_client.post(
        "/constables/me/location",
        json={
            "longitude": 80.6050,
            "latitude": 16.5050,
            "accuracy": 5.0,
            "sequence_number": 1,
        },
        headers=constable_headers,
    )
    assert loc1.status_code == 200, loc1.text
    data1 = loc1.json()
    assert data1["geographic_zone"] == "ZONE-MAIN-GATE"
    assert data1["zone_status"] == "CONFIRMED"

    # Verify constable document state in DB
    updated_c = await models.Constable.get(constable.id)
    assert updated_c.current_geographic_zone == "ZONE-MAIN-GATE"

    # Step 2: Roam to Temple Sanctum: [80.6250, 16.5050]
    loc2 = await full_client.post(
        "/constables/me/location",
        json={
            "longitude": 80.6250,
            "latitude": 16.5050,
            "accuracy": 8.0,
            "sequence_number": 2,
        },
        headers=constable_headers,
    )
    assert loc2.status_code == 200
    data2 = loc2.json()
    assert data2["geographic_zone"] == "ZONE-TEMPLE"
    assert data2["zone_status"] == "CONFIRMED"

    # Step 3: Out-of-order sequence packet (sequence_number 1 arrives after 2)
    loc3 = await full_client.post(
        "/constables/me/location",
        json={
            "longitude": 80.6050,
            "latitude": 16.5050,
            "accuracy": 5.0,
            "sequence_number": 1,
        },
        headers=constable_headers,
    )
    assert loc3.status_code == 200
    # Constable's latest state must NOT have regressed to Main Gate
    c_after_ooo = await models.Constable.get(constable.id)
    assert c_after_ooo.current_geographic_zone == "ZONE-TEMPLE"

    # Step 4: Fix with high inaccuracy (> 50m) does not jump zone
    loc4 = await full_client.post(
        "/constables/me/location",
        json={
            "longitude": 80.6050,
            "latitude": 16.5050,
            "accuracy": 120.0,  # poor accuracy
            "sequence_number": 3,
        },
        headers=constable_headers,
    )
    assert loc4.status_code == 200
    data4 = loc4.json()
    assert data4["zone_status"] == "UNCERTAIN"
    # Remains in previously confirmed Temple zone due to hysteresis policy
    assert data4["geographic_zone"] == "ZONE-TEMPLE"


async def test_overlapping_zones_resolve_by_priority(full_client, make_user, auth_header):
    await make_user(phone="zone_admin_prio", password="pw", role="admin")
    admin_headers = await auth_header("zone_admin_prio", "pw")

    # Zone A: Priority 5
    zone_a = {
        "code": "ZONE-LOW-PRIO",
        "name": "General Area",
        "coordinates": [
            [
                [80.5000, 16.5000],
                [80.5200, 16.5000],
                [80.5200, 16.5200],
                [80.5000, 16.5200],
                [80.5000, 16.5000],
            ]
        ],
        "priority": 5,
        "enabled": True,
    }
    await full_client.post("/event-zones/", json=zone_a, headers=admin_headers)

    # Zone B: Priority 20 (overlapping inside Zone A)
    zone_b = {
        "code": "ZONE-HIGH-PRIO",
        "name": "VIP Sanctum",
        "coordinates": [
            [
                [80.5050, 16.5050],
                [80.5150, 16.5050],
                [80.5150, 16.5150],
                [80.5050, 16.5150],
                [80.5050, 16.5050],
            ]
        ],
        "priority": 20,
        "enabled": True,
    }
    await full_client.post("/event-zones/", json=zone_b, headers=admin_headers)

    from app.services.zones import detect_geographic_zone

    # Point inside both Zone A and Zone B: [80.5100, 16.5100]
    code, status, _ = await detect_geographic_zone(80.5100, 16.5100, accuracy=5.0)
    assert code == "ZONE-HIGH-PRIO"
    assert status == "CONFIRMED"

    # Point inside Zone A only: [80.5010, 16.5010]
    code2, status2, _ = await detect_geographic_zone(80.5010, 16.5010, accuracy=5.0)
    assert code2 == "ZONE-LOW-PRIO"
    assert status2 == "CONFIRMED"

    # Point outside both: [80.6000, 16.6000]
    code3, status3, _ = await detect_geographic_zone(80.6000, 16.6000, accuracy=5.0)
    assert code3 is None
    assert status3 == "OUTSIDE"
