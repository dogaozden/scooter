"""
BLE scanner for discovering Ninebot scooters.

Uses bleak to scan for BLE devices advertising the Nordic UART Service
(NUS) or matching known Ninebot/Segway device name patterns.
"""

from __future__ import annotations

import asyncio
import sys

from bleak import BleakScanner

# Nordic UART Service UUIDs (used by F-series Ninebot)
NUS_SERVICE_UUID = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
NUS_RX_UUID = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"  # Write TO scooter
NUS_TX_UUID = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"  # Notify FROM scooter

# Legacy UUIDs (older models)
LEGACY_SERVICE_UUID = "0000ffe0-0000-1000-8000-00805f9b34fb"
LEGACY_CHAR_UUID = "0000ffe1-0000-1000-8000-00805f9b34fb"

# Known name patterns for Ninebot / Segway scooters
_NAME_PATTERNS = ("Ninebot", "Segway", "N5G", "NAGSF2")


def _is_ninebot_device(name: str | None, service_uuids: list[str]) -> bool:
    """Check whether a discovered device looks like a Ninebot scooter."""
    if name:
        for pattern in _NAME_PATTERNS:
            if pattern.lower() in name.lower():
                return True

    nus_lower = NUS_SERVICE_UUID.lower()
    for uuid in service_uuids:
        if uuid.lower() == nus_lower:
            return True

    return False


async def scan_for_scooters(timeout: float = 10.0) -> list[dict]:
    """Scan for Ninebot scooters over BLE.

    Parameters
    ----------
    timeout:
        Maximum scan duration in seconds.

    Returns
    -------
    list[dict]
        A list of dicts with keys ``name``, ``address``, and ``rssi``
        for each discovered scooter.
    """
    results: list[dict] = []
    seen_addresses: set[str] = set()

    def _detection_callback(device, advertisement_data):
        if device.address in seen_addresses:
            return

        name = device.name or advertisement_data.local_name or ""
        service_uuids = advertisement_data.service_uuids or []

        if _is_ninebot_device(name, service_uuids):
            seen_addresses.add(device.address)
            entry = {
                "name": name or "Unknown",
                "address": device.address,
                "rssi": advertisement_data.rssi,
            }
            results.append(entry)
            print(
                f"  Found: {entry['name']} "
                f"[{entry['address']}] "
                f"(RSSI: {entry['rssi']} dBm)"
            )

    # On macOS 12.x+, background BLE scanning requires filtering by
    # service UUID to work reliably (CoreBluetooth bug workaround).
    scanner_kwargs: dict = {
        "detection_callback": _detection_callback,
    }
    if sys.platform == "darwin":
        scanner_kwargs["service_uuids"] = [NUS_SERVICE_UUID]

    print(f"Scanning for Ninebot scooters ({timeout}s)...")
    scanner = BleakScanner(**scanner_kwargs)
    await scanner.start()
    await asyncio.sleep(timeout)
    await scanner.stop()

    if not results:
        print("No Ninebot scooters found.")
    else:
        print(f"Scan complete. Found {len(results)} device(s).")

    return results


async def select_scooter(timeout: float = 10.0) -> tuple[str, str] | None:
    """Scan for scooters and let the user pick one.

    If only one device is found it is selected automatically.
    If multiple are found, the user is prompted with a numbered list.

    Parameters
    ----------
    timeout:
        Maximum scan duration in seconds.

    Returns
    -------
    tuple[str, str] | None
        ``(address, name)`` of the selected scooter, or ``None`` if no
        devices were discovered.
    """
    devices = await scan_for_scooters(timeout)

    if not devices:
        return None

    if len(devices) == 1:
        chosen = devices[0]
        print(f"Auto-selecting: {chosen['name']} [{chosen['address']}]")
        return chosen["address"], chosen["name"]

    # Multiple devices -- prompt the user
    print("\nMultiple scooters found:")
    for i, dev in enumerate(devices, start=1):
        print(f"  {i}. {dev['name']} [{dev['address']}] (RSSI: {dev['rssi']} dBm)")

    while True:
        try:
            raw = input(f"\nSelect scooter (1-{len(devices)}): ").strip()
            idx = int(raw)
            if 1 <= idx <= len(devices):
                chosen = devices[idx - 1]
                print(f"Selected: {chosen['name']} [{chosen['address']}]")
                return chosen["address"], chosen["name"]
            print(f"Please enter a number between 1 and {len(devices)}.")
        except (ValueError, EOFError):
            print("Invalid input. Please enter a number.")
            continue
