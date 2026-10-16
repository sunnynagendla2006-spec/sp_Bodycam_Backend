"""
SP Bodycam network telemetry collector.

A small standalone service meant to run on a computer on the SITE'S LAN. It
polls or subscribes to the site's network equipment through a vendor adapter,
normalizes what it sees into association events, snapshots and AP health
observations, buffers them durably on local disk, and forwards them to the
control-room backend over HTTPS with its own per-collector credential.

Only the Python standard library is used, so it installs anywhere Python 3.10+
runs. It does not import the backend application.

Run:   python -m collector          (configuration comes from COLLECTOR_* environment variables)
Docs:  docs/NETWORK_MONITORING_PLATFORM.md and collector/README.md
"""
__version__ = "0.1.0"
