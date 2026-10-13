# ARVI-SENTINELS — Physical Access Point Integration Guide
**Wireless Telemetry Ingestion, Controller Configuration & Field Acceptance Testing**
**Andhra Pradesh Police Department | Jathara & Public Event Communications**

---

## 1. Scope & System Architecture

This guide specifies the technical integration requirements for connecting physical enterprise Wi-Fi controllers and outdoor access points (APs) deployed from a Mobile Command Vehicle to the ARVI-SENTINELS backend.

```
+-----------------------------------------------------------------------------------------+
|                               FIELD DEPLOYMENT TOPOLOGY                                 |
|                                                                                         |
|   +-----------------------+          +-----------------------+                          |
|   |   Outdoor AP #1       |          |   Outdoor AP #2       |                          |
|   |  (Sector: Main Gate)  |          |  (Sector: Temple Q)   |                          |
|   +-----------+-----------+          +-----------+-----------+                          |
|               | PoE (Cat6/Optic)                 | PoE (Cat6/Optic)                     |
|               v                                  v                                      |
|   +----------------------------------------------------------+                          |
|   |    Hardened Managed Switch (VLAN 10: Mgmt, VLAN 20: Police WLAN, VLAN 30: Telemetry) |
|   +-----------------------------+----------------------------+                          |
|                                 |                                                       |
|                                 v                                                       |
|   +----------------------------------------------------------+                          |
|   |       Physical Controller / Edge Collector Daemon        |                          |
|   |     (Captures Syslog / RADIUS Acct / SNMP / Webhooks)    |                          |
|   +-----------------------------+----------------------------+                          |
|                                 | HTTPS + X-Edge-Controller-Key                         |
|                                 v                                                       |
|   +----------------------------------------------------------+                          |
|   |       FastAPI Backend (/telemetry/ap-events endpoints)   |                          |
|   |   - Validates Edge Key & Monotonic Skew (±300s)          |                          |
|   |   - Deduplicates Controller Event IDs                    |                          |
|   |   - Resolves Enrolled Device (802.1X Identity / MAC)     |                          |
|   |   - Updates Constable AP Association & Publishes WS      |                          |
|   +----------------------------------------------------------+                          |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Hardware Prerequisites & Supported Controllers

ARVI-SENTINELS employs a vendor-neutral ingestion boundary. The command vehicle may utilize any enterprise wireless infrastructure supporting standard Syslog, RADIUS Accounting, or REST webhooks.

### Supported Controller Matrix

| Vendor / Platform | Supported Ingestion Methods | Required Firmware / Features | Recommended Setup |
| :--- | :--- | :--- | :--- |
| **Aruba / HPE** (ArubaOS 8/10, Instant On) | Syslog (`ap-events/syslog`), RADIUS Acct, REST Webhook | ArubaOS >= 8.10.x, WPA3-Enterprise 802.1X | Forward Syslog to Edge Collector on UDP 514 |
| **Cisco Catalyst** (9800 Series, Meraki) | Syslog, RADIUS Acct (RFC 2866), Telemetry Streaming | IOS-XE >= 17.6.x | Enable RADIUS Accounting interim-updates every 60s |
| **Ubiquiti UniFi** (UDM Pro / Cloud Gateway) | Syslog (`ap-events/syslog`), Webhooks via Controller API | UniFi Network >= 7.5.x | Syslog export to vehicle collector |
| **MikroTik RouterOS** (CAPsMAN) | Syslog, RADIUS Accounting | RouterOS v7.12+ (Wireless/WiFi-QCOM) | CAPsMAN client association/disassociation logging |
| **Ruckus / CommScope** (SmartZone) | Syslog, Event API, RADIUS Acct | SmartZone 5.2+ | Event forwarder or syslog stream |

---

## 3. Edge Telemetry Adapter Ingestion Boundary

The backend exposes dedicated edge ingestion endpoints mounted at `/telemetry`:

| Endpoint | Method | Input Source | Description |
| :--- | :--- | :--- | :--- |
| `/telemetry/ap-events` | `POST` | Generic Edge Collector | Ingests a single normalised association/disassociation/roam event. |
| `/telemetry/ap-events/batch` | `POST` | Edge Collector Batch | Ingests up to 100 events in a single HTTP transaction. |
| `/telemetry/ap-events/syslog` | `POST` | Syslog Daemon Forwarder | Ingests raw syslog messages from Aruba, Cisco, UniFi, or MikroTik. |
| `/telemetry/ap-events/radius` | `POST` | FreeRADIUS / Radiator Webhook | Ingests RFC 2866 Accounting Start/Stop/Interim attributes. |
| `/telemetry/events` | `GET` | Operator Audit Log | Returns queryable history of ingested edge controller events. |

### Edge Security & Authentication Rules
1. **Dedicated Service Credential**: Requests must supply the header:
   ```http
   X-Edge-Controller-Key: <EDGE_CONTROLLER_API_KEY>
   ```
2. **Rejection of Constable Tokens**: Constable JWT tokens are strictly rejected on `/telemetry/*` to prevent spoofing.
3. **Timestamp Validation & Replay Defense**:
   - Event `occurred_at` must fall within `±300 seconds` (configurable via `EDGE_CONTROLLER_MAX_SKEW_SECONDS`) of the server clock.
   - `controller_event_id` is deduplicated via MongoDB unique index on `EdgeControllerEventLog`.
4. **MAC Randomization Handling**: Android phones utilize randomized MAC addresses. The ingestion engine resolves the constable identity by checking:
   - Primary: 802.1X `authenticated_identity` (e.g., constable phone number `9876543210` or officer badge ID).
   - Secondary: Explicit `device_identifier` matching enrolled device record.
   - Tertiary: Static MAC fallback for fixed legacy devices.
   - Unmapped MACs are safely recorded as `unmapped_device` and do NOT generate phantom devices.

---

## 4. Syslog Forwarder Configuration (Command Vehicle Daemon)

In the command vehicle, a lightweight rsyslog or python forwarder receives syslog from APs on UDP 514 and posts to the local backend:

```python
# Minimal Vehicle Edge Collector Forwarder (scripts/edge_syslog_forwarder.py)
import os, re, socket, requests

BACKEND_URL = os.getenv("BACKEND_TELEMETRY_URL", "http://127.0.0.1:8000/telemetry/ap-events/syslog")
EDGE_KEY = os.getenv("EDGE_CONTROLLER_API_KEY", "your-secure-edge-key")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 514))
print("ARVI-SENTINELS Edge Syslog Collector listening on UDP 514...")

while True:
    data, addr = sock.recvfrom(4096)
    raw_message = data.decode("utf-8", errors="ignore").strip()
    try:
        resp = requests.post(
            BACKEND_URL,
            headers={"X-Edge-Controller-Key": EDGE_KEY, "Content-Type": "application/json"},
            json={"raw_message": raw_message, "controller_id": f"ctrl-{addr[0]}"},
            timeout=2.0
        )
    except Exception as exc:
        print(f"Forwarding error: {exc}")
```

---

## 5. Physical Acceptance Test Runbooks (Tests A–G)

> [!IMPORTANT]
> In accordance with Stage 2 instructions, physical hardware tests (Tests A, B, D, E) are labeled **PENDING PHYSICAL HARDWARE TESTING** until verified with physical APs on site. Tests C, F, G have been verified programmatically.

### Test A — Real AP Telemetry (Status: PENDING PHYSICAL HARDWARE)
- **Objective**: Prove that an enrolled phone's association with a physical AP reaches the backend and updates the LiveMap without manual refresh.
- **Hardware Setup**: Connect Cisco/Aruba AP to switch port on VLAN 20. Register AP BSSID `00:11:22:33:44:55` as "AP-GATE-01" in `AccessPoint` collection.
- **Action**: Officer phone joins the SSID `AP-POLICE-SECURE` using 802.1X credentials.
- **Expected Outcome**:
  1. AP logs association event to syslog.
  2. Edge collector submits to `POST /telemetry/ap-events/syslog`.
  3. Response returns `status: "processed"`.
  4. LiveMap displays AP badge `AP-GATE-01 (PHYSICAL_CONTROLLER)`.

### Test B — Zone Movement & Hysteresis (Status: PENDING PHYSICAL HARDWARE)
- **Objective**: Walk an officer phone between physical AP sectors (e.g., Main Gate -> Temple Queue).
- **Expected Outcome**:
  1. Handoff event arrives at backend.
  2. Map updates AP association without jumping or flickering.
  3. GNSS geographic zone updates according to GPS coordinates independently of the AP association.

### Test C — Live-Map Real-Time Updates (Status: VERIFIED PROGRAMMATICALLY)
- **Objective**: Verify that location beacons arriving via REST trigger immediate WebSocket marker movements on the operator screen.
- **Outcome**: Confirmed in test suite [LiveMap.test.jsx](file:///home/user/github/personal/Arvi-sentinels/sp_Bodycam_frontend/src/test/LiveMap.test.jsx) and [test_event_zones.py](file:///home/user/github/personal/Arvi-sentinels/sp_Bodycam_Backend/tests/test_event_zones.py). WebSocket event `constable.location_updated` updates state immediately without REST polling.

### Test D — Internet Disconnected Blackout (Status: PENDING PHYSICAL HARDWARE / VERIFIED ARCHITECTURALLY)
- **Objective**: Cut satellite/cellular WAN uplink.
- **Outcome**: Local Docker Compose stack maintains local database, local tile server, and local WebSocket delivery without WAN connectivity.

### Test E — AP Failure & Fallback (Status: PENDING PHYSICAL HARDWARE)
- **Objective**: Power down an AP (e.g., unplug PoE cable).
- **Outcome**:
  1. Edge collector ingests disassociation event or heartbeat timeout.
  2. Officer state transitions from "Live (<60s)" to "Delayed (60-300s)" and finally "Stale (>300s)".

### Test F — Recording Policy Invariant (Status: VERIFIED PROGRAMMATICALLY)
- **Objective**: Confirm that NO video or audio recording is triggered by AP association, roaming, or location updates.
- **Outcome**: The codebase has zero automatic recording triggers. Recording is strictly isolated to deliberate SOS emergency button actuation.

### Test G — Replay & Recovery (Status: VERIFIED PROGRAMMATICALLY)
- **Objective**: Confirm that duplicate or replayed edge controller events are rejected.
- **Outcome**: Verified in [test_ap_telemetry.py](file:///home/user/github/personal/Arvi-sentinels/sp_Bodycam_Backend/tests/test_ap_telemetry.py). Duplicate `controller_event_id` returns `duplicate_ignored` with HTTP `200` and does not fire duplicate handoff events.

---

## 6. Virtual AP Simulator Status

The virtual AP simulation engine ([app/services/ap_association.py](file:///home/user/github/personal/Arvi-sentinels/sp_Bodycam_Backend/app/services/ap_association.py)) remains available for training and unit tests. All simulated events are explicitly stamped with `source: PresenceEventSource.simulated ("SIMULATED")` and can never be confused with physical controller telemetry (`PHYSICAL_CONTROLLER`).
