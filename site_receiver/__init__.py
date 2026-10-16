"""
SP Bodycam SITE RECEIVER.

A small, separate FastAPI service that runs on a site's LAN. Phones upload recorded video chunks to it while the control
room is unreachable; it verifies, durably stores and acknowledges them, then forwards them to the control room when
backhaul returns. It does NOT import the control-room application and never connects to its database: it talks to the
control room only through the documented /receiver/v1 API with its own credential.

Run:   uvicorn site_receiver.main:app --host 0.0.0.0 --port 8443 --ssl-keyfile ... --ssl-certfile ...
Docs:  site_receiver/README.md and docs/BODYCAM_OFFLINE_TRANSPORT.md
"""
__version__ = "0.1.0"
