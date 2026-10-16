# Network telemetry collector

A standalone service for the **site's LAN computer**. It reads the site's network equipment through an
adapter, buffers durably on disk, and forwards to the control-room backend over HTTPS with its own
credential. Standard library only (Python 3.10+). Not runtime-verified.

```
network equipment --(adapter)--> collector --(SQLite buffer)--> HTTPS --> backend /collector/*
```

## Run

From the `backend/` directory (the parent of this package):

```
python -m collector
```

## Configuration (environment variables)

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `COLLECTOR_BACKEND_URL` | yes | | Backend base URL. Must be `https://` unless `COLLECTOR_ALLOW_INSECURE_HTTP=true` |
| `COLLECTOR_TOKEN` or `COLLECTOR_TOKEN_FILE` | yes | | The credential shown once when the collector was created in the dashboard. Prefer the file (mode 600) |
| `COLLECTOR_ADAPTER` | yes | | Adapter kind, e.g. `synthetic` (development only) |
| `COLLECTOR_ADAPTER_CONFIG` | no | | Path to a JSON file with adapter settings (no secrets in the dashboard, none in source) |
| `COLLECTOR_SITE_CODE` | no | | Optional cross-check; the backend still takes the site from the credential and rejects a mismatch |
| `COLLECTOR_POLL_INTERVAL_SECONDS` | no | 5 | Adapter poll period |
| `COLLECTOR_HEARTBEAT_SECONDS` | no | 30 | Heartbeat period (capabilities, adapter health, buffer depth, drops) |
| `COLLECTOR_BATCH_SIZE` | no | 100 | Events per upload (max 200) |
| `COLLECTOR_BUFFER_PATH` | no | `collector-buffer.sqlite3` | Local durable queue |
| `COLLECTOR_MAX_BUFFER_ITEMS` | no | 200000 | Oldest items are dropped (and counted in heartbeats) above this |
| `COLLECTOR_HTTP_TIMEOUT_SECONDS` | no | 10 | Per-request timeout |
| `COLLECTOR_BACKOFF_BASE_SECONDS` / `COLLECTOR_BACKOFF_MAX_SECONDS` | no | 2 / 300 | Exponential retry with jitter |
| `COLLECTOR_CA_FILE` | no | | Extra CA bundle for a private backend certificate |
| `COLLECTOR_ALLOW_SYNTHETIC` | no | false | Must be `true` to run the simulated adapter |
| `COLLECTOR_LOG_LEVEL` | no | INFO | JSON-lines logs on stdout (the token is never logged) |

## Adapters

| Kind | Status |
|---|---|
| `synthetic` | **Simulated data for development.** Labelled SIMULATED end to end. |
| `example_skeleton` | A template; refuses to start. Copy it to build a real adapter (see its docstring). |

There is **no production vendor adapter yet.** Writing one needs the chosen equipment's documented API,
credentials and hardware to verify against. See `adapters/base.py` for the contract.

## Delivery guarantees

At-least-once, oldest first. Items are stored before upload and removed only after the backend accepted
them; the backend de-duplicates by `event_id`/`snapshot_id`. During an outage everything buffers; on
recovery it is replayed in order. A credential problem (401/403) pauses uploads but keeps buffering.
Payloads the backend permanently refuses are quarantined (bounded) instead of blocking the queue.

## Example service unit (illustrative; adjust paths and user)

```
[Unit]
Description=SP network telemetry collector
After=network-online.target

[Service]
WorkingDirectory=/opt/sp/backend
EnvironmentFile=/etc/sp-collector/collector.env
ExecStart=/usr/bin/python3 -m collector
Restart=always
User=spcollector

[Install]
WantedBy=multi-user.target
```
