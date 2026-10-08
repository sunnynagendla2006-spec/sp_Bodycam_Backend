"""Deployment metadata CRUD + RBAC."""
import pytest

pytestmark = pytest.mark.usefixtures("mongo_db")


async def test_admin_can_create_deployment(full_client, make_user, auth_header):
    await make_user(phone="dep0000001", password="pw", role="admin")
    headers = await auth_header("dep0000001", "pw")
    resp = await full_client.post("/deployments/", json={"name": "JATARA-TEST-001", "is_demo": True}, headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["name"] == "JATARA-TEST-001"
    assert body["status"] == "active"
    assert body["zone_count"] == 0
    assert body["access_point_count"] == 0


async def test_duplicate_deployment_name_rejected(full_client, make_user, auth_header, make_deployment):
    await make_deployment(name="DUP-DEPLOY-01")
    await make_user(phone="dep0000002", password="pw", role="admin")
    headers = await auth_header("dep0000002", "pw")
    resp = await full_client.post("/deployments/", json={"name": "DUP-DEPLOY-01"}, headers=headers)
    assert resp.status_code == 409


@pytest.mark.parametrize("role", ["station", "constable", "citizen"])
async def test_non_admin_cannot_create_deployment(full_client, make_user, auth_header, role):
    await make_user(phone=f"dep0001{role}", password="pw", role=role)
    headers = await auth_header(f"dep0001{role}", "pw")
    resp = await full_client.post("/deployments/", json={"name": "X"}, headers=headers)
    assert resp.status_code == 403


async def test_station_cannot_list_deployments(full_client, make_user, auth_header):
    await make_user(phone="dep0000003", password="pw", role="station")
    headers = await auth_header("dep0000003", "pw")
    resp = await full_client.get("/deployments/", headers=headers)
    assert resp.status_code == 403


async def test_deployment_counts_reflect_registered_access_points(full_client, make_user, auth_header, make_deployment, make_access_point):
    await make_deployment(name="COUNT-DEPLOY-01")
    await make_access_point(code="AP-CD-1", zone="ZONE-A", deployment="COUNT-DEPLOY-01")
    await make_access_point(code="AP-CD-2", zone="ZONE-B", deployment="COUNT-DEPLOY-01")
    await make_user(phone="dep0000004", password="pw", role="admin")
    headers = await auth_header("dep0000004", "pw")

    resp = await full_client.get("/deployments/", headers=headers)
    assert resp.status_code == 200
    row = next(d for d in resp.json() if d["name"] == "COUNT-DEPLOY-01")
    assert row["zone_count"] == 2
    assert row["access_point_count"] == 2


async def test_update_deployment_status(full_client, make_user, auth_header, make_deployment):
    deployment = await make_deployment(name="UPD-DEPLOY-01")
    await make_user(phone="dep0000005", password="pw", role="admin")
    headers = await auth_header("dep0000005", "pw")

    resp = await full_client.patch(f"/deployments/{deployment.id}", json={"status": "ended"}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "ended"
