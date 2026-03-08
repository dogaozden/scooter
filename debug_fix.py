#!/usr/bin/env python3
"""Debug script: try every approach to clear OVP and enable balancing."""

import asyncio
import logging
import struct

logging.basicConfig(level=logging.DEBUG, format="%(name)s %(levelname)s: %(message)s")
logging.getLogger("bleak").setLevel(logging.WARNING)

from ninebot_bms.scanner import select_scooter
from ninebot_bms.connection import NinebotConnection
from ninebot_bms.protocol import (
    ADDR_PC, ADDR_BMS, ADDR_ESC,
    CMD_READ, CMD_WRITE, CMD_WRITE_NO_REPLY, CMD_CLEAR_ERROR, CMD_MCU_RESET,
    build_packet, build_read_cmd, parse_packet,
)

# Key registers
BAT_STATUS = 0x30
BAT_BALANCE = 0x36
BAT_UNDERVOLT = 0x37
BAT_OVERVOLT = 0x38
BAT_CELL_BASE = 0x40


async def read_u16(conn, reg, name=""):
    data = await conn.read_reg(ADDR_BMS, reg, 2)
    if data and len(data) >= 2:
        val = struct.unpack_from("<H", data)[0]
        print(f"  READ 0x{reg:02X} ({name}): 0x{val:04X} ({val})")
        return val
    print(f"  READ 0x{reg:02X} ({name}): FAILED")
    return None


async def try_write(conn, reg, value, name="", method="write"):
    """Try writing and report result."""
    if method == "write":
        pkt = build_packet(ADDR_PC, ADDR_BMS, CMD_WRITE, reg, struct.pack("<H", value))
        print(f"  WRITE 0x{reg:02X} ({name}) <- 0x{value:04X} [CMD_WRITE]")
        resp = await conn.request(pkt, timeout=3.0, retries=1)
        if resp:
            print(f"    -> GOT RESPONSE: cmd=0x{resp['cmd']:02X} data={resp['data'].hex()}")
            return True
        print(f"    -> No response")
    elif method == "write_nr":
        pkt = build_packet(ADDR_PC, ADDR_BMS, CMD_WRITE_NO_REPLY, reg, struct.pack("<H", value))
        print(f"  WRITE 0x{reg:02X} ({name}) <- 0x{value:04X} [CMD_WRITE_NO_REPLY]")
        await conn.send_packet(pkt)
        await asyncio.sleep(0.5)

    # Read back
    after = await read_u16(conn, reg, f"{name} readback")
    if after is not None and after == value:
        print(f"    -> SUCCESS! Value changed to 0x{value:04X}")
        return True
    elif after is not None:
        print(f"    -> Value unchanged: 0x{after:04X}")
    return False


async def main():
    print("=" * 60)
    print("  DEBUG FIX: OVP Clear + Forced Balancing")
    print("=" * 60)

    # --- Connect ---
    result = await select_scooter(timeout=8.0)
    if not result:
        print("No scooter found!")
        return
    address, name = result

    conn = NinebotConnection()
    if not await conn.connect(address, device_name=name):
        print("Connection failed!")
        return

    if not await conn.authenticate():
        print("Auth failed!")
        await conn.disconnect()
        return

    print("\n" + "=" * 60)
    print("  PHASE 1: Read current state")
    print("=" * 60)

    status = await read_u16(conn, BAT_STATUS, "BAT_STATUS")
    balance = await read_u16(conn, BAT_BALANCE, "BAT_BALANCE")
    uv = await read_u16(conn, BAT_UNDERVOLT, "BAT_UNDERVOLT")
    ov = await read_u16(conn, BAT_OVERVOLT, "BAT_OVERVOLT")

    # Read cell voltages
    print("\n  Cell voltages:")
    cell_data = await conn.read_reg(ADDR_BMS, BAT_CELL_BASE, 20)
    cells = []
    if cell_data and len(cell_data) >= 20:
        for i in range(10):
            mv = struct.unpack_from("<H", cell_data, i * 2)[0]
            cells.append(mv)
            flag = " <<<" if mv > 4100 or mv < 3200 else ""
            print(f"    Cell {i+1}: {mv}mV ({mv/1000:.3f}V){flag}")

    # Also read registers 0x31-0x35 to understand what's writable
    print("\n  Other BMS registers:")
    for reg in range(0x31, 0x3A):
        await read_u16(conn, reg, f"reg_0x{reg:02X}")

    print("\n" + "=" * 60)
    print("  PHASE 2: Try writing to various registers")
    print("=" * 60)

    # --- 2a: Try writing BAT_BALANCE to force Cell 9 balancing ---
    # Cell 9 = bit 8 (0-indexed), so bitmask = 0x0100
    print("\n--- 2a: Force Cell 9 balancing (BAT_BALANCE = 0x0100) ---")
    await try_write(conn, BAT_BALANCE, 0x0100, "BAT_BALANCE", "write")
    await try_write(conn, BAT_BALANCE, 0x0100, "BAT_BALANCE", "write_nr")

    # --- 2b: Try clearing BAT_OVERVOLT ---
    print("\n--- 2b: Clear BAT_OVERVOLT bitmap ---")
    await try_write(conn, BAT_OVERVOLT, 0x0000, "BAT_OVERVOLT", "write")
    await try_write(conn, BAT_OVERVOLT, 0x0000, "BAT_OVERVOLT", "write_nr")

    # --- 2c: Try CMD_CLEAR_ERROR ---
    print("\n--- 2c: CMD_CLEAR_ERROR (0x06) ---")
    pkt = build_packet(ADDR_PC, ADDR_BMS, CMD_CLEAR_ERROR, 0x00)
    print(f"  Sending CMD_CLEAR_ERROR...")
    resp = await conn.request(pkt, timeout=3.0, retries=1)
    if resp:
        print(f"  -> Response: cmd=0x{resp['cmd']:02X}")
    else:
        print(f"  -> No response (sending no-reply version too)")
        await conn.send_packet(pkt)
        await asyncio.sleep(0.5)

    # Read status after clear_error
    status_after = await read_u16(conn, BAT_STATUS, "BAT_STATUS after CLEAR_ERROR")

    # --- 2d: Try writing BAT_STATUS with WRITE_LOCK set ---
    print("\n--- 2d: Set WRITE_LOCK (0x0010) then clear OVP ---")
    if status is not None:
        wl_val = status | 0x0010  # set WRITE_LOCK
        await try_write(conn, BAT_STATUS, wl_val, "BAT_STATUS+WRITE_LOCK", "write")
        await try_write(conn, BAT_STATUS, wl_val, "BAT_STATUS+WRITE_LOCK", "write_nr")

        # Try clearing protections now
        status2 = await read_u16(conn, BAT_STATUS, "BAT_STATUS re-read")
        if status2 is not None:
            clear_val = status2 & ~0x0700  # clear all protection bits
            await try_write(conn, BAT_STATUS, clear_val, "BAT_STATUS cleared", "write")
            await try_write(conn, BAT_STATUS, clear_val, "BAT_STATUS cleared", "write_nr")

    # --- 2e: Try writing to ESC error register ---
    print("\n--- 2e: Try ESC error clear ---")
    pkt = build_packet(ADDR_PC, ADDR_ESC, CMD_CLEAR_ERROR, 0x00)
    print(f"  Sending CMD_CLEAR_ERROR to ESC...")
    resp = await conn.request(pkt, timeout=3.0, retries=1)
    if resp:
        print(f"  -> Response: cmd=0x{resp['cmd']:02X}")
    else:
        print(f"  -> No response")

    # --- 2f: Register scan - try writing 0x0000 to every writable-looking reg ---
    print("\n--- 2f: Probe writable registers (write 0 to 0x31-0x39) ---")
    for reg in [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39]:
        before = await read_u16(conn, reg, f"0x{reg:02X} before")
        if before is not None and before != 0:
            # Try writing 0
            pkt = build_packet(ADDR_PC, ADDR_BMS, CMD_WRITE_NO_REPLY, reg, struct.pack("<H", 0))
            await conn.send_packet(pkt)
            await asyncio.sleep(0.3)
            after = await read_u16(conn, reg, f"0x{reg:02X} after write 0")
            if after is not None and after != before:
                print(f"    *** REGISTER 0x{reg:02X} IS WRITABLE! {before} -> {after} ***")

    print("\n" + "=" * 60)
    print("  PHASE 3: Final state")
    print("=" * 60)
    await read_u16(conn, BAT_STATUS, "BAT_STATUS")
    await read_u16(conn, BAT_BALANCE, "BAT_BALANCE")
    await read_u16(conn, BAT_OVERVOLT, "BAT_OVERVOLT")

    await conn.disconnect()
    print("\nDone!")


if __name__ == "__main__":
    asyncio.run(main())
