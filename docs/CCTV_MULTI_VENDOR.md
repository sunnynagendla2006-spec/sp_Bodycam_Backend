# Multi-Vendor CCTV Integration

## 1. Problem

Real deployments mix camera brands — Hikvision, Dahua, Axis, Reolink,
generic ONVIF/RTSP units. The Control Room needs one unified dashboard
regardless of manufacturer, without the operator opening each vendor's
own app.

## 2. Supported protocols

- **ONVIF** (`provider_type: onvif`) — the standardized device-management
  protocol most IP cameras speak regardless of brand. Connectivity is
  verified with a real `GetSystemDateAndTime` SOAP probe (the one ONVIF
  device-service call the spec guarantees works without authentication) —
  see `app/services/cctv_providers.py::ONVIFProvider`.
- **Generic RTSP** (`provider_type: rtsp`) — a real RTSP `OPTIONS`
  handshake over a raw TCP socket — see `RTSPProvider` in the same file.
- **NVR / VMS** (`provider_type: nvr` / `vms`) — declared in the schema as
  genuine future extension points. Calling either today raises
  `NotImplementedError` with a clear message; nothing fakes a working
  integration for them.

`manufacturer`/`model` on a camera are **informational only** — they
never change which provider/protocol code path handles the camera (see
`models.CCTVCamera`'s docstring). A "Hikvision" camera that only speaks
RTSP is registered with `provider_type: rtsp`; nothing here assumes a
vendor name implies a capability.

## 3. Camera capabilities

Every camera carries an explicit `capabilities` object
(`onvif`/`rtsp`/`ptz`/`audio`/`snapshot`/`multiple_streams`), all
`false` by default. A capability is only ever set to `true` from a real
probe result (`POST /cctv/cameras/{id}/test`) — never assumed from
`provider_type` or `manufacturer`. Today's probes can only confirm
`onvif` or `rtsp` reachability; `ptz`/`audio`/`snapshot`/
`multiple_streams` require protocol-level work this phase doesn't
implement (ONVIF Media/PTZ service calls), so they stay `false` and the
UI honestly shows "PTZ NOT SUPPORTED" rather than rendering
non-functional controls.

## 4. Adding a camera

### Generic RTSP
`POST /cctv/cameras` with `provider_type: rtsp`, `stream_host`,
`stream_port` (default 554), optional `stream_path`. Test with
`POST /cctv/cameras/{id}/test` — a real RTSP OPTIONS probe.

### ONVIF
Same endpoint with `provider_type: onvif`. Set `management_url` to the
camera's device service URL (e.g.
`http://192.168.1.50:80/onvif/device_service`); if omitted, the backend
guesses `http://{stream_host}:80/onvif/device_service` (the ONVIF-spec
default path — a reasonable guess, not a guarantee, which is exactly why
the real probe decides the actual result, not the guess itself).

## 5. Local network discovery

`POST /cctv/discover` (admin-only) sends a real WS-Discovery UDP
multicast probe (`239.255.255.250:3702`) and parses real `ProbeMatch`
responses — see `app/services/cctv_discovery.py`. This is inherently
link-local (WS-Discovery cannot cross a router/the internet) and is
additionally filtered to `CCTV_ALLOWED_NETWORKS` before any result is
returned. It only surfaces **candidates** — nothing is auto-registered;
the admin reviews and explicitly calls `POST /cctv/cameras` for any
device they choose to add.

## 6. Security

- Credentials (`username`/password) are never returned by any API
  response — only `credentials_configured: bool`. The password is
  Fernet-encrypted at rest (`app/services/cctv_security.py`) and never
  logged.
- Every camera network target (`stream_host:port`, and the ONVIF
  `management_url`'s host:port) is validated against
  `CCTV_ALLOWED_NETWORKS` — an explicit admin-configured allowlist,
  fail-closed (unset = nothing validates). A fixed block list (cloud
  metadata endpoints, multicast, unspecified ranges) applies
  unconditionally on top of that allowlist. See
  `cctv_security.py::validate_stream_target`.
- WS-Discovery is restricted the same way: a response from an address
  outside `CCTV_ALLOWED_NETWORKS` is silently dropped.

## 7. Media gateway (browser playback)

**Not configured in this environment.** `start_stream()` on every
provider (RTSP and ONVIF alike) honestly returns `ok: False` with a
clear error — there is no MediaMTX/LiveKit-Ingress/WebRTC-HLS bridge
wired up here. The session lifecycle, RBAC, audit trail, and WebSocket
events (`cctv.stream_requested`, `cctv.stream_failed`) are fully real and
testable without one. Wiring in a real gateway (MediaMTX is a reasonable
choice — it speaks RTSP-in, WebRTC/HLS-out) is a clearly-scoped future
integration, deliberately **not** attempted here rather than guessed at
and shipped half-working. The existing bodycam LiveKit pipeline
(`app/routers/live_stream.py`) is untouched and is a different, unrelated
pipeline — bodycams publish via their own LiveKit client SDK, which has
no code path for pulling in an existing RTSP/ONVIF camera stream.

## 8. Offline / local-only operation

Nothing in this subsystem requires internet access: MongoDB, the FastAPI
backend, and camera network targets are all expected to be reachable on
the same local/event network. `CCTV_ALLOWED_NETWORKS` is exactly the
mechanism that scopes this to a local deployment's own subnets. This was
not separately load-tested with the WAN link physically disconnected in
this environment.

## 9. Limitations (honest, not aspirational)

- **No physical camera of any brand was available to test against** in
  this environment. Every "online"/"ONVIF-compatible" result in this
  session's testing came from either this project's own demo RTSP
  listener or a local Python test server built specifically to speak one
  real ONVIF SOAP call — never a real Hikvision/Dahua/Axis/Reolink
  device. Do not read any vendor name mentioned in this document as "this
  vendor was tested" — see the final verification report for exactly
  what was and wasn't tested.
- **No vendor-specific adapter exists** (Hikvision/Dahua/Axis/Reolink
  proprietary SDKs/APIs). Per the project's own policy, one would only be
  built if a camera genuinely required it (i.e. had no ONVIF/RTSP path)
  and a real device were available to validate against.
- **No media gateway** — see §7.
- **PTZ/audio/snapshot/multi-stream** are modeled but unimplemented at
  the protocol level (no ONVIF Media/PTZ/Imaging service calls) — see §3.
- `manufacturer`/`model` are free-text, admin-entered metadata, not
  verified against the device itself.
