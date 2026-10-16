# ARVI-SENTINELS — Mobile Client Integration & Contract Guide
**Android / Flutter Police Officer Client Specification & Dependency Audit**
**Andhra Pradesh Police Department**

---

## 1. Mobile Application Dependency Audit (Task 6)

### Audit Finding
An exhaustive search of the `Arvi-sentinels` repository confirms that **no native Android, iOS, or Flutter application source code exists within this repository**.

- **Repository Structure**:
  - `sp_Bodycam_Backend`: FastAPI + MongoDB/Beanie backend engine.
  - `sp_Bodycam_frontend`: Vite + React + Leaflet control room operator application.
- **Dependency Classification**: External Client System.
- **Status**: The mobile client is developed/managed in a separate mobile repository or provisioned through an enterprise mobile device management (MDM) profile.

> [!IMPORTANT]
> Backend integration tests and frontend simulation tests run independently using authenticated test fixtures and synthetic location payloads. However, physical auto-joining of Wi-Fi networks and hardware button SOS activation require the native Android client application.

---

## 2. Canonical Location Reporting Contract (`POST /constables/me/location`)

The mobile client must transmit regular location beacons while the officer is on active duty.

### HTTP Request Specification
- **URL**: `POST /constables/me/location`
- **Headers**:
  ```http
  Authorization: Bearer <OFFICER_JWT_TOKEN>
  Content-Type: application/json
  ```

### Canonical Request Payload
```json
{
  "latitude": 13.62885,
  "longitude": 79.41922,
  "accuracy": 12.5,
  "recorded_at": "2026-10-13T12:30:00.000Z",
  "sequence_number": 142,
  "duty_session_id": "session_670b8a1c9d",
  "device_identifier": "DEV-AP-POLICE-0842",
  "battery_level": 88,
  "network_type": "WIFI",
  "source": "GNSS"
}
```

### Field Requirements & Validation Rules
| Field | Type | Mandatory | Validation Rule |
| :--- | :--- | :--- | :--- |
| `latitude` | `float` | Yes | WGS84 latitude between `-90.0` and `90.0`. |
| `longitude` | `float` | Yes | WGS84 longitude between `-180.0` and `180.0`. |
| `accuracy` | `float` | Yes | Estimated horizontal 1-sigma radius in meters. Values `> 50.0m` cause the backend zone detector to enter `UNCERTAIN` state to prevent false zone triggers. |
| `recorded_at` | `datetime` | Yes | ISO 8601 UTC timestamp recorded by device GNSS clock. Rejected if clock skew exceeds `±300 seconds`. |
| `sequence_number` | `int` | Yes | Monotonically increasing counter per device session. Rejects out-of-order or duplicate sequence numbers from overwriting the latest live location. |
| `duty_session_id` | `str` | Optional | Active duty session identifier obtained from `GET /constables/me/duty-session`. |
| `device_identifier` | `str` | Optional | Persistent hardware/MDM device serial. |
| `battery_level` | `int` | Optional | Battery percentage (`0-100`). |
| `network_type` | `str` | Optional | `"WIFI"`, `"CELLULAR"`, or `"OFFLINE"`. |
| `source` | `str` | Optional | Position source: `"GNSS"`, `"CELL"`, or `"NETWORK"`. |

### Server Response (`200 OK`)
```json
{
  "status": "recorded",
  "constable_id": "670b8a1c9d4e2f1a3c000101",
  "geographic_zone": "MAIN_GATE",
  "zone_confidence": "HIGH",
  "zone_changed": false,
  "sequence_number": 142,
  "received_at": "2026-10-13T12:30:00.120Z"
}
```

---

## 3. Recording Policy Invariant & SOS Activation

> [!CAUTION]
> **STRICT POLICY**: The mobile client must NEVER trigger audio or video recording automatically.
> - Geographic zone entry/exit must NEVER trigger recording.
> - Wi-Fi AP association or roaming must NEVER trigger recording.
> - Remote control room triggers must NEVER silently activate officer recording without user consent.

### Authorized Recording Trigger
Recording starts **ONLY** when the officer performs a deliberate physical action on the device:
1. Long-press of dedicated emergency shortcut (e.g., simultaneous Power + Volume Down for 3 seconds).
2. Explicit tap on the red SOS button within the application UI with confirmation haptic feedback.

When triggered, the app calls `POST /recordings/sos`, begins local buffered video capture, and uploads segmented 10-second chunks to `POST /recordings/{recording_id}/chunks`.

---

## 4. Enterprise Wi-Fi Auto-Join & Roaming Provisioning

For smooth field operation at festival sites without officer intervention, police devices should be provisioned using **WPA3-Enterprise / 802.1X** or **Wi-Fi Passpoint (Hotspot 2.0)**:

### 1. 802.1X EAP Profile (via Android Enterprise / MDM)
- **SSID**: `AP-POLICE-EVENT-SECURE`
- **Security**: WPA3-Enterprise (or WPA2-Enterprise with PMF mandatory)
- **EAP Method**: PEAP with MSCHAPv2 (or EAP-TLS with officer client certificates)
- **CA Certificate**: Internal Andhra Pradesh Police Root CA
- **Identity**: Constable Phone Number / Badge ID (e.g., `AP-POLICE-0842`)
- **Anonymous Identity**: `anonymous@police.ap.gov.in`

### 2. MAC Address Randomization Constraint
Android 10+ randomizes MAC addresses by default per SSID.
- If EAP-TLS / 802.1X PEAP is used, the edge telemetry adapter correlates the officer session via the **802.1X User-Name / Authenticated Identity**, regardless of MAC address rotation.
- If pre-shared key (WPA2/3-PSK) is used during pilots, the MDM policy must set **MAC Randomization: "Use device MAC"** for the authorized event SSID to enable correlation.

---

## 5. Offline Queuing & Reconnection Policy

When an officer moves into a deep shadow zone or underground passage where Wi-Fi signal is lost:
1. **Local SQLite / Room Buffer**: The mobile app stores location beacons locally, tagging each with its timestamp and sequential `sequence_number`.
2. **Backoff & Reconnect**: Upon re-establishing Wi-Fi connectivity to any authorized AP:
   - The app fetches a fresh JWT if expired.
   - It transmits the *latest current fix* first to immediately refresh the LiveMap.
   - It flushes historical buffered beacons in the background.
3. **Backend Idempotency**: The backend accepts the historical beacons into the `ConstableLocation` audit trail without overwriting the latest live position projection on `Constable`.
