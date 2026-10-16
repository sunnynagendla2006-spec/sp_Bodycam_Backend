"""
Storage planning aid for a site receiver:   python -m site_receiver.capacity --devices 40 --hours 8 --outage-days 3

Prints how much disk a receiver needs to hold every phone's video for an outage, using:
    bytes = bitrate/8 * 3600 * hours_per_device_per_day * devices * outage_days * (1 + overhead)
The default bitrate is a PLANNING FIGURE, not a measurement: measure your phones' real segment sizes
(e.g. the median size of the .mp4 chunks in <storage_root>) and pass --bitrate-kbps accordingly.
Needs only the standard library. Nothing here touches the network or the receiver's data.
"""
import argparse


def estimate(bitrate_kbps: float, devices: int, hours: float, outage_days: float, overhead: float = 0.10) -> dict:
    per_device_day = bitrate_kbps * 1000 / 8 * 3600 * hours
    total = per_device_day * devices * outage_days * (1 + overhead)
    return {"per_device_per_day_gib": per_device_day / 1024 ** 3, "total_gib": total / 1024 ** 3, "total_bytes": int(total)}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bitrate-kbps", type=float, default=4000, help="average video+audio bitrate per phone (default 4000, a planning figure)")
    ap.add_argument("--devices", type=int, default=10)
    ap.add_argument("--hours", type=float, default=8, help="recording hours per device per day")
    ap.add_argument("--outage-days", type=float, default=3, help="how long the backhaul may be down")
    ap.add_argument("--overhead", type=float, default=0.10, help="filesystem/metadata overhead fraction")
    a = ap.parse_args()
    r = estimate(a.bitrate_kbps, a.devices, a.hours, a.outage_days, a.overhead)
    print(f"Per device per day: {r['per_device_per_day_gib']:.2f} GiB")
    print(f"Needed for {a.devices} devices, {a.hours} h/day, {a.outage_days} days outage: {r['total_gib']:.1f} GiB")
    print("Add headroom for RECEIVER_MIN_FREE_MB and for the retention period of already-synced video.")


if __name__ == "__main__":
    main()
