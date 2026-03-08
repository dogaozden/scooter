"""
Debug script to probe the Ninebot F2 Pro's BLE GATT services,
characteristics, and test various communication approaches.
"""
import asyncio
import sys
from bleak import BleakClient, BleakScanner


async def main():
    target_name = "NAGSF2430C0153"

    # Step 1: Scan and find the scooter
    print(f"Scanning for {target_name}...")
    devices = await BleakScanner.discover(timeout=10.0, return_adv=True)
    target = None
    for d, adv in devices.values():
        if d.name and target_name in d.name:
            target = d
            print(f"  Found: {d.name} [{d.address}] RSSI={adv.rssi}")
            break

    if not target:
        print("Scooter not found!")
        return

    # Step 2: Connect and enumerate ALL services
    print(f"\nConnecting to {target.address}...")
    client = BleakClient(target.address, timeout=30.0)
    await client.connect()
    print(f"Connected: {client.is_connected}")

    print("\n" + "=" * 60)
    print("GATT SERVICE ENUMERATION")
    print("=" * 60)

    writable_chars = []
    notify_chars = []

    for service in client.services:
        print(f"\nService: {service.uuid}")
        print(f"  Description: {service.description}")
        for char in service.characteristics:
            props = ", ".join(char.properties)
            print(f"  Char: {char.uuid} [{props}]")
            print(f"    Handle: {char.handle}")
            if "read" in char.properties:
                try:
                    val = await client.read_gatt_char(char.uuid)
                    # Try to show as ASCII if printable, else hex
                    try:
                        text = val.decode("utf-8", errors="replace")
                        print(f"    Value: {val.hex()} ('{text}')")
                    except Exception:
                        print(f"    Value: {val.hex()}")
                except Exception as e:
                    print(f"    Read error: {e}")

            if "write" in char.properties or "write-without-response" in char.properties:
                writable_chars.append(char)
            if "notify" in char.properties or "indicate" in char.properties:
                notify_chars.append(char)

            for desc in char.descriptors:
                print(f"    Descriptor: {desc.uuid} = {desc}")

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"\nWritable characteristics ({len(writable_chars)}):")
    for c in writable_chars:
        print(f"  {c.uuid} [{', '.join(c.properties)}]")
    print(f"\nNotifiable characteristics ({len(notify_chars)}):")
    for c in notify_chars:
        print(f"  {c.uuid} [{', '.join(c.properties)}]")

    # Step 3: Try reading the GAP device name
    print("\n" + "=" * 60)
    print("DEVICE NAME ATTEMPTS")
    print("=" * 60)
    print(f"  From scan: {target.name}")

    gap_uuid = "00002a00-0000-1000-8000-00805f9b34fb"
    try:
        name_bytes = await client.read_gatt_char(gap_uuid)
        print(f"  From GAP char: {name_bytes} ('{name_bytes.decode('utf-8', errors='replace')}')")
    except Exception as e:
        print(f"  GAP char read failed: {e}")

    # Step 4: Subscribe to ALL notify characteristics and send test packets
    print("\n" + "=" * 60)
    print("COMMUNICATION TEST")
    print("=" * 60)

    received_data = {}

    def make_handler(char_uuid):
        def handler(sender, data):
            hex_str = data.hex()
            print(f"  << NOTIFY [{char_uuid[-8:]}]: {hex_str} ({len(data)} bytes)")
            if char_uuid not in received_data:
                received_data[char_uuid] = []
            received_data[char_uuid].append(bytes(data))
        return handler

    # Subscribe to all notifiable characteristics
    for char in notify_chars:
        try:
            await client.start_notify(char.uuid, make_handler(char.uuid))
            print(f"  Subscribed to {char.uuid}")
        except Exception as e:
            print(f"  Failed to subscribe to {char.uuid}: {e}")

    # Wait a moment to see if there's any unsolicited data
    print("\n  Waiting 3s for unsolicited notifications...")
    await asyncio.sleep(3.0)

    if not received_data:
        print("  No unsolicited data received.")
    else:
        print(f"  Received unsolicited data on {len(received_data)} characteristic(s)")

    # Step 5: Try sending raw Ninebot packets (UNENCRYPTED)
    # Build a simple read command: read 2 bytes from ESC register 0x1A (firmware version)
    from ninebot_bms.protocol import (
        build_read_cmd, build_packet, format_packet_hex,
        ADDR_APP, ADDR_ESC, ADDR_BMS, ADDR_BLE,
        CMD_READ, CMD_INIT, CMD_PING,
    )

    test_packets = [
        ("Read ESC FW version (0x1A)", build_read_cmd(ADDR_ESC, 0x1A, 2)),
        ("Read BMS serial (0x10)", build_read_cmd(ADDR_BMS, 0x10, 14)),
        ("Read BMS voltage (0x34)", build_read_cmd(ADDR_BMS, 0x34, 2)),
        ("Raw INIT to BLE module", build_packet(ADDR_APP, ADDR_BLE, CMD_INIT, 0x00)),
    ]

    for desc, packet in test_packets:
        received_data.clear()
        print(f"\n  >> Sending: {desc}")
        print(f"     Packet: {format_packet_hex(packet)}")

        for char in writable_chars:
            try:
                print(f"     Writing to {char.uuid}...")
                # Fragment if needed
                for i in range(0, len(packet), 20):
                    chunk = packet[i:i+20]
                    await client.write_gatt_char(char.uuid, chunk, response=False)
                    if i + 20 < len(packet):
                        await asyncio.sleep(0.02)

                # Wait for response
                await asyncio.sleep(2.0)

                if received_data:
                    print(f"     GOT RESPONSE!")
                    for uuid, datas in received_data.items():
                        for d in datas:
                            print(f"       [{uuid[-8:]}]: {d.hex()}")
                    break  # Found the right characteristic
                else:
                    print(f"     No response on this characteristic.")
            except Exception as e:
                print(f"     Write failed: {e}")

        if not received_data:
            print(f"     No response on any characteristic.")

    # Step 6: Try with NinebotCrypto INIT using the CORRECT device name
    print("\n" + "=" * 60)
    print("NINEBOTCRYPTO INIT TEST (with correct device name)")
    print("=" * 60)

    from miauth.nb.nbcrypto import NbCrypto
    from miauth.nb.nbcommand import NbCommand

    # Try with the scan name
    for name_candidate in [target.name.encode(), target.name.encode("utf-8")[:16]]:
        received_data.clear()
        print(f"\n  Using device name: {name_candidate!r}")

        crypto = NbCrypto()
        crypto.set_name(name_candidate)

        init_cmd = NbCommand.CMD_INIT
        init_encrypted = crypto.encrypt(init_cmd)
        print(f"  INIT raw:       {init_cmd.hex()}")
        print(f"  INIT encrypted: {init_encrypted.hex()}")

        for char in writable_chars:
            try:
                for i in range(0, len(init_encrypted), 20):
                    chunk = init_encrypted[i:i+20]
                    await client.write_gatt_char(char.uuid, chunk, response=False)
                    if i + 20 < len(init_encrypted):
                        await asyncio.sleep(0.02)

                await asyncio.sleep(3.0)

                if received_data:
                    print(f"  GOT RESPONSE with name {name_candidate!r}!")
                    for uuid, datas in received_data.items():
                        for d in datas:
                            print(f"    [{uuid[-8:]}]: {d.hex()}")
                    break
                else:
                    print(f"  No response on {char.uuid}")
            except Exception as e:
                print(f"  Write failed: {e}")

    # Cleanup
    print("\n" + "=" * 60)
    print("CLEANUP")
    print("=" * 60)
    for char in notify_chars:
        try:
            await client.stop_notify(char.uuid)
        except Exception:
            pass
    await client.disconnect()
    print("Disconnected. Debug complete.")


if __name__ == "__main__":
    asyncio.run(main())
