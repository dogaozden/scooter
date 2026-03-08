"""Focused debug: step through the NinebotCrypto auth handshake."""
import asyncio
import secrets
from bleak import BleakClient, BleakScanner
from miauth.nb.nbcrypto import NbCrypto
from miauth.nb.nbcommand import NbCommand

SCOOTER_NAME = "NAGSF2430C0153"
NUS_RX = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
NUS_TX = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"


async def main():
    # --- Find and connect ---
    print("Scanning...")
    devices = await BleakScanner.discover(timeout=10.0, return_adv=True)
    target = None
    for d, adv in devices.values():
        if d.name and SCOOTER_NAME in d.name:
            target = d
            break
    if not target:
        print("Scooter not found!")
        return

    client = BleakClient(target.address, timeout=30.0)
    await client.connect()
    print(f"Connected to {target.name} [{target.address}]")

    # --- Setup notification handler ---
    buf = bytearray()
    response_future = None

    def on_notify(sender, data):
        nonlocal buf, response_future
        print(f"  << NOTIFY: {data.hex()} ({len(data)} bytes)")
        if data[:2] == b"\x5a\xa5":
            buf[:] = data
        else:
            buf.extend(data)

        # Check completeness: encrypted msg = buf[2] + 13
        if len(buf) >= 3:
            expected = buf[2] + 13
            print(f"     buf[2]=0x{buf[2]:02x}={buf[2]}, expected_total={expected}, have={len(buf)}")
            if len(buf) >= expected:
                print(f"     COMPLETE! Total: {len(buf)} bytes")
                if response_future and not response_future.done():
                    response_future.set_result(bytes(buf))
                buf.clear()

    await client.start_notify(NUS_TX, on_notify)

    async def send_and_wait(data, timeout=5.0):
        nonlocal buf, response_future
        buf.clear()
        loop = asyncio.get_running_loop()
        response_future = loop.create_future()
        # Fragment into 20-byte chunks
        for i in range(0, len(data), 20):
            chunk = data[i:i+20]
            await client.write_gatt_char(NUS_RX, chunk, response=False)
            if i + 20 < len(data):
                await asyncio.sleep(0.02)
        try:
            result = await asyncio.wait_for(response_future, timeout=timeout)
            return result
        except asyncio.TimeoutError:
            print(f"     TIMEOUT! buf has {len(buf)} bytes: {buf.hex()}")
            return None
        finally:
            response_future = None

    # --- Init crypto ---
    crypto = NbCrypto()
    device_name = target.name.encode("utf-8")
    crypto.set_name(device_name)
    app_key = secrets.token_bytes(16)

    print(f"\nDevice name: {device_name!r}")
    print(f"App key: {app_key.hex()}")

    # --- Stage 1: INIT ---
    print("\n=== STAGE 1: INIT ===")
    init_cmd = NbCommand.CMD_INIT
    print(f"  Raw INIT:       {init_cmd.hex()}")
    init_enc = crypto.encrypt(init_cmd)
    print(f"  Encrypted INIT: {init_enc.hex()}")
    print(f"  >> Sending INIT...")

    init_resp = await send_and_wait(init_enc)
    if init_resp is None:
        print("  INIT FAILED - no response")
        await client.disconnect()
        return

    print(f"  Raw response: {init_resp.hex()}")

    # Decrypt
    try:
        init_dec = crypto.decrypt(init_resp)
        print(f"  Decrypted: {init_dec.hex()}")
    except Exception as e:
        print(f"  Decrypt FAILED: {e}")
        await client.disconnect()
        return

    # Parse
    ack_len = NbCommand.ACK_LEN  # 7
    cmd_header = init_dec[:ack_len]
    payload = init_dec[ack_len:]
    print(f"  Header (7 bytes): {cmd_header.hex()}")
    print(f"  Expected ACK_INIT: {NbCommand.ACK_INIT.hex()}")
    print(f"  Match: {cmd_header == NbCommand.ACK_INIT}")
    print(f"  Payload ({len(payload)} bytes): {payload.hex()}")

    if len(payload) >= 16:
        ble_key = payload[:16]
        serial = payload[16:]
        print(f"  BLE key: {ble_key.hex()}")
        print(f"  Serial: {serial.hex()} ('{serial.decode('utf-8', errors='replace')}')")
    else:
        print(f"  Payload too short for BLE key!")
        await client.disconnect()
        return

    # Update crypto with BLE key
    crypto.set_ble_data(ble_key)
    print(f"  Crypto updated with BLE key")

    # --- Stage 2: PING ---
    print("\n=== STAGE 2: PING ===")
    ping_cmd = NbCommand.CMD_PING(app_key)
    print(f"  Raw PING:       {ping_cmd.hex()}")
    ping_enc = crypto.encrypt(ping_cmd)
    print(f"  Encrypted PING: {ping_enc.hex()} ({len(ping_enc)} bytes)")
    print(f"  >> Sending PING...")

    ping_resp = await send_and_wait(ping_enc, timeout=8.0)
    if ping_resp is None:
        print("  PING FAILED - no response")
        # Try again with a longer timeout
        print("\n  Retrying PING with 10s timeout...")
        ping_enc2 = crypto.encrypt(NbCommand.CMD_PING(app_key))
        print(f"  Encrypted PING (retry): {ping_enc2.hex()}")
        ping_resp = await send_and_wait(ping_enc2, timeout=10.0)
        if ping_resp is None:
            print("  PING retry FAILED")

            # Try sending raw unencrypted PING as a test
            print("\n  Trying raw (unencrypted) PING...")
            raw_ping = NbCommand.CMD_PING(app_key)
            raw_resp = await send_and_wait(raw_ping, timeout=5.0)
            if raw_resp:
                print(f"  Got raw PING response: {raw_resp.hex()}")
            else:
                print("  Raw PING also failed")

            await client.disconnect()
            return

    print(f"  Raw PING response: {ping_resp.hex()}")

    try:
        ping_dec = crypto.decrypt(ping_resp)
        print(f"  Decrypted: {ping_dec.hex()}")
    except Exception as e:
        print(f"  Decrypt FAILED: {e}")
        await client.disconnect()
        return

    ping_header = ping_dec[:ack_len]
    print(f"  Header: {ping_header.hex()}")
    print(f"  ACK_PRE (not paired): {NbCommand.ACK_PRE.hex()}")
    print(f"  ACK_PING (paired):    {NbCommand.ACK_PING.hex()}")

    if ping_header == NbCommand.ACK_PRE:
        print("  >> NOT PAIRED — need to press power button")
        print("\n=== STAGE 3: PAIR ===")
        print("  >>> PRESS THE POWER BUTTON ON YOUR SCOOTER NOW! <<<")

        for attempt in range(15):
            pair_cmd = NbCommand.CMD_PAIR(serial)
            pair_enc = crypto.encrypt(pair_cmd)
            print(f"\n  Pair attempt {attempt+1}/15...")
            print(f"  Encrypted PAIR: {pair_enc.hex()}")

            pair_resp = await send_and_wait(pair_enc, timeout=3.0)
            if pair_resp:
                print(f"  Raw response: {pair_resp.hex()}")
                try:
                    pair_dec = crypto.decrypt(pair_resp)
                    print(f"  Decrypted: {pair_dec.hex()}")
                    pair_header = pair_dec[:ack_len]
                    print(f"  Header: {pair_header.hex()}")
                    if pair_header == NbCommand.ACK_PAIR or pair_header == NbCommand.ACK_PING:
                        print("  PAIRED SUCCESSFULLY!")
                        break
                except Exception as e:
                    print(f"  Decrypt failed: {e}")
            await asyncio.sleep(2.0)

    elif ping_header == NbCommand.ACK_PING:
        print("  >> ALREADY PAIRED!")
    else:
        print(f"  >> UNEXPECTED RESPONSE")

    # Finalize
    crypto.set_app_data(app_key)
    print("\n=== AUTH COMPLETE ===")
    print("Crypto finalized with app key")

    # --- Test: try reading a register ---
    print("\n=== TEST: Read BMS voltage (reg 0x34) ===")
    from ninebot_bms.protocol import build_read_cmd, parse_packet, ADDR_BMS
    read_pkt = build_read_cmd(ADDR_BMS, 0x34, 2)
    print(f"  Raw read cmd: {read_pkt.hex()}")
    enc_read = crypto.encrypt(read_pkt)
    print(f"  Encrypted: {enc_read.hex()}")

    read_resp = await send_and_wait(enc_read, timeout=5.0)
    if read_resp:
        print(f"  Raw response: {read_resp.hex()}")
        try:
            dec_read = crypto.decrypt(read_resp)
            print(f"  Decrypted: {dec_read.hex()}")
            parsed = parse_packet(dec_read)
            if parsed:
                print(f"  Parsed: cmd=0x{parsed['cmd']:02x} reg=0x{parsed['reg']:02x} data={parsed['data'].hex()}")
                if len(parsed['data']) >= 2:
                    voltage_raw = int.from_bytes(parsed['data'][:2], 'little')
                    print(f"  VOLTAGE: {voltage_raw / 100:.2f} V")
        except Exception as e:
            print(f"  Parse failed: {e}")
    else:
        print("  No response to read command")

    await client.stop_notify(NUS_TX)
    await client.disconnect()
    print("\nDone!")


if __name__ == "__main__":
    asyncio.run(main())
