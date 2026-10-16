# SP Bodycam Site Receiver

A small on-premises service that accepts bodycam video chunks from phones over the site LAN/Wi-Fi when the internet
backhaul is down, stores them durably, and forwards them to the central control room when the backhaul returns.

**Status:** written, not executed. No tests, builds or runtime validation were performed on this code.

## What it does
- Verifies the phone's *offline grant* (ES256, signed by the control room) with the control room's **public** key. No
  control-room contact is needed at upload time.
- Accepts chunks via `PUT /v1/recordings/{recording_id}/chunks/{chunk_id}`; verifies size + SHA-256, fsyncs, renames
  atomically, commits SQLite metadata, and **only then** acknowledges (`locally_durable`).
- Idempotent: the same chunk id + hash returns a duplicate acknowledgement; a different hash is rejected (409
  `hash_conflict`) and never overwrites existing evidence.
- Forwards to central (`/receiver/v1/*`) with exponential back-off + jitter; marks `central_acknowledged` only after the
  control room confirms identical content. Conflicts/corruption are quarantined, never silently dropped.
- Heartbeats to central (disk, queue, last sync) and receives grant revocations and operator commands.
- Optional site-local LiveKit token issuing (`/v1/live/start`). Without it the receiver offers *delayed* chunk playback
  only (`/v1/admin/.../stream`) — that is near-live at best, not live.

## Run (later, by the operator)
```
pip install -r site_receiver/requirements.txt
RECEIVER_SITE_ID=... RECEIVER_SITE_CODE=... RECEIVER_CENTRAL_URL=https://control.example \
RECEIVER_CENTRAL_TOKEN_FILE=/etc/receiver/central.token RECEIVER_GRANT_PUBLIC_KEY_FILE=/etc/receiver/grant_pub.pem \
RECEIVER_ACCESS_TOKEN_SECRET_FILE=/etc/receiver/session.secret RECEIVER_ADMIN_KEY_FILE=/etc/receiver/admin.key \
uvicorn site_receiver.main:app --host 0.0.0.0 --port 8443 --ssl-keyfile key.pem --ssl-certfile cert.pem --workers 1
```
Use **one worker**. Keep the receiver's clock synced (NTP). Do not expose it to the internet. Secrets come from the
environment or `*_FILE` paths; none are in source.

See `docs/BODYCAM_OFFLINE_TRANSPORT.md` for architecture, TLS/VPN, storage sizing and limitations.
