# ARVI-SENTINELS — Local-Only Offline Deployment Guide
**Command Vehicle & Field Operation (Jatharas, Festivals & Crowd Events)**
**Andhra Pradesh Police Department**

---

## 1. Architectural Overview & Zero-WAN Resilience

During large-scale public events, jatharas, or remote festival grounds in Andhra Pradesh, commercial cellular backhaul often degrades or fails completely due to cell-tower congestion. The **ARVI-SENTINELS Command Vehicle LAN** is engineered to operate in **100% Air-Gapped / Offline Local Mode**.

```
+-----------------------------------------------------------------------------------+
|                           COMMAND VEHICLE LOCAL AREA NETWORK                      |
|                                                                                   |
|  +--------------------+        +---------------------+      +------------------+  |
|  |  Police Constables |  WiFi  | Outdoor APs / Edge  | Eth  | Managed Switch   |  |
|  |  (Bodycams / Mobile|<======>| Controller Cluster  |<====>| (VLAN 10/20/30)  |  |
|  +--------------------+        +---------------------+      +--------+---------+  |
|                                                                      |            |
|  +-------------------------------------------------------------------+            |
|  |                                                                                |
|  v                                                                                |
|  +--------------------+        +---------------------+      +------------------+  |
|  | Edge Telemetry     | Eth    | FastAPI Backend     | Eth  | MongoDB Replica  |  |
|  | Ingestion Adapter  |=======>| (Local Event Engine)|<====>| Set (rs0 / Local)|  |
|  +--------------------+        +----------+----------+      +------------------+  |
|                                           |                                       |
|                                           | WebSocket / REST                      |
|                                           v                                       |
|                                +---------------------+      +------------------+  |
|                                | Vite/React Operator | Eth  | Local Offline    |  |
|                                | LiveMap Dashboard   |<====>| Tile Server      |  |
|                                +---------------------+      | (mbtileserver)   |  |
|                                                             +------------------+  |
+-----------------------------------------------------------------------------------+
```

### Core Invariants
1. **Zero External Scraping**: Dashboard map rendering does not query public OpenStreetMap or third-party CDNs. Maps are served locally from containerized MBTiles packages.
2. **Local Multi-Document Transactions**: MongoDB runs as a local single-node replica set (`rs0`) on the vehicle server to support atomic transactions required by Beanie and Motor.
3. **Local Media & Evidence Storage**: Audio and video chunks uploaded following deliberate emergency shortcut activations are written to persistent host-mounted storage (`./uploads`) with SHA-256 integrity validation.
4. **Recording Policy**: The system strictly records audio/video only upon explicit officer actuation of the emergency shortcut. Location reporting and AP roaming never trigger media capture.

---

## 2. Docker Compose Infrastructure

The local-only deployment is orchestrated via two compose files:
- [docker-compose.yml](file:///home/user/github/personal/Arvi-sentinels/docker-compose.yml): Core database, backend, frontend, local LiveKit daemon, and initialization tasks.
- [docker-compose.offline-tiles.yml](file:///home/user/github/personal/Arvi-sentinels/docker-compose.offline-tiles.yml): Extension for the local vector/raster offline tile server (`consbio/mbtileserver`).

### Services Inventory

| Service | Port | Description | Healthcheck / Readiness |
| :--- | :--- | :--- | :--- |
| `mongodb` | `27017` | MongoDB 7.0 with `--replSet rs0` | `mongosh --eval 'db.adminCommand("ping")'` |
| `mongo-init` | *N/A* | One-shot replica set initiator | Runs `rs.initiate()` and exits `0` |
| `livekit` | `7880`, `7881`, `7882` | LiveKit Server (`--dev` offline mode) | Local WebRTC signaling & media relay |
| `backend` | `8000` | FastAPI Backend (`app.main:app`) | `curl -f http://localhost:8000/docs` |
| `frontend` | `5173` | React/Vite Control Room Operator UI | HTTP `200` on `/` |
| `tile-server` *(opt)* | `8080` | Local offline MBTiles server | `curl -f http://localhost:8080/health` |

---

## 3. Offline Map Tile Setup (Pre-Deployment)

To comply with public safety data sovereignty and prevent tile-server rate limiting:

1. **Obtain Approved Event Map Package**:
   Extract an `.mbtiles` package for the operational area (e.g., Tirupati, Vijayawada, Srisailam, Rajahmundry) using tools such as OpenMapTiles, Planetiler, or official Survey of India cartographic data.
2. **Mount the MBTiles File**:
   Place the `.mbtiles` file in `./tiles/event-map.mbtiles`:
   ```bash
   mkdir -p ./tiles
   cp /media/usb/andhra_pradesh_district.mbtiles ./tiles/event-map.mbtiles
   ```
3. **Configure Environment**:
   In `sp_Bodycam_frontend/.env`:
   ```env
   VITE_MAP_TILE_URL=http://<VEHICLE_LAN_IP>:8080/services/event-map/tiles/{z}/{x}/{y}.png
   ```

---

## 4. Startup & Shutdown Runbook

### Prerequisites
- Docker Engine >= 24.0.0 and Docker Compose V2 installed.
- Host machine network configured with a static LAN IP (e.g., `192.168.10.2`).
- Firewall rules permitting ports `8000` (Backend), `5173` (Frontend), `8080` (Tiles), `7880-7882` (LiveKit) on the Vehicle LAN interface (`eth0`).

### Step-by-Step Startup Procedure

```bash
# 1. Navigate to the repository root
cd /home/user/github/personal/Arvi-sentinels

# 2. Verify environment configuration files
test -f sp_Bodycam_Backend/.env || cp sp_Bodycam_Backend/.env.example sp_Bodycam_Backend/.env
test -f sp_Bodycam_frontend/.env || cp sp_Bodycam_frontend/.env.example sp_Bodycam_frontend/.env

# 3. Launch Core Infrastructure (MongoDB & Replica Set Init)
docker compose up -d mongodb mongo-init

# 4. Confirm MongoDB Replica Set Status
docker compose exec mongodb mongosh --eval "rs.status().members[0].stateStr"
# Expected Output: "PRIMARY"

# 5. Launch Full Stack (with offline tiles if package is present)
docker compose -f docker-compose.yml -f docker-compose.offline-tiles.yml up -d

# 6. Verify Service Health
docker compose ps
```

### Clean Shutdown Procedure

```bash
# Graceful shutdown preserving volumes and database state
docker compose -f docker-compose.yml -f docker-compose.offline-tiles.yml down

# Verify all containers have stopped
docker compose ps
```

---

## 5. Local Database Backup & Restore Procedure

In event deployments, all mission telemetry, event zones, audit logs, and officer location histories must be archived at the end of each duty shift.

### Automated Hot Backup (`mongodump`)

```bash
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_DIR="./backups/shift_${TIMESTAMP}"
mkdir -p "${BACKUP_DIR}"

# Execute mongodump against the running replica set
docker compose exec mongodb mongodump \
  --db arvi_sentinels \
  --out /data/db/backup_tmp

# Move backup to host storage / external USB
docker compose exec mongodb mv /data/db/backup_tmp/arvi_sentinels /data/db/shift_${TIMESTAMP}
docker cp $(docker compose ps -q mongodb):/data/db/shift_${TIMESTAMP} "${BACKUP_DIR}"
docker compose exec mongodb rm -rf /data/db/shift_${TIMESTAMP}

echo "Backup complete: ${BACKUP_DIR}"
```

### Restoration Procedure (`mongorestore`)

```bash
BACKUP_PATH="./backups/shift_20261013_180000"

# Copy backup directory into container
docker cp "${BACKUP_PATH}" $(docker compose ps -q mongodb):/data/db/restore_target

# Execute mongorestore with drop flag to reconstruct exact state
docker compose exec mongodb mongorestore \
  --db arvi_sentinels \
  --drop \
  /data/db/restore_target

# Cleanup temp files
docker compose exec mongodb rm -rf /data/db/restore_target

echo "Database restoration complete."
```

---

## 6. LAN Blackout & Recovery Validation (Test D)

### Test Objective
Verify that cutting the vehicle's satellite/cellular WAN uplink does not disrupt control-room operations or officer tracking over the physical Wi-Fi network.

### Execution Steps
1. **Baseline**: Observe LiveMap operator dashboard on `http://192.168.10.2:5173`. Markers for active constables show status "Live (<60s)".
2. **Sever WAN**: Physically disconnect the WAN Ethernet cable or run `ip link set dev eth1 down` on the command vehicle gateway.
3. **Simulate Location Updates**:
   Officer devices continue sending location beacons to `http://192.168.10.2:8000/constables/me/location`.
4. **Observation**:
   - HTTP response code: `200 OK` (processed without timeouts).
   - LiveMap UI updates coordinates and geographic zone immediately via WebSocket (`ws://192.168.10.2:8000/ws/alerts`).
   - Map tiles continue rendering smoothly from local tile cache.
5. **Restore WAN**: Re-enable WAN interface. Confirm zero data loss and uninterrupted local tracking.
