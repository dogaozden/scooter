#!/usr/bin/env python3
"""
Interactive CLI for the Ninebot F2 Pro BMS Diagnostic & Repair Tool.

Usage:
    python cli.py
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys

# Enable DEBUG logging for our modules so we can see what's happening
logging.basicConfig(
    level=logging.DEBUG,
    format="%(name)s %(levelname)s: %(message)s",
)
# Quiet down noisy third-party loggers
logging.getLogger("bleak").setLevel(logging.WARNING)
logging.getLogger("miauth").setLevel(logging.WARNING)

from ninebot_bms.scanner import scan_for_scooters, select_scooter
from ninebot_bms.connection import NinebotConnection
from ninebot_bms.bms import BMSDiagnostic
from ninebot_bms.commands import BMSCommands

# ── ANSI colour helpers ─────────────────────────────────────────────────────

GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def ok(msg: str) -> str:
    return f"{GREEN}  ✅ {msg}{RESET}"


def err(msg: str) -> str:
    return f"{RED}  ❌ {msg}{RESET}"


def warn(msg: str) -> str:
    return f"{YELLOW}  ⚠️  {msg}{RESET}"


def info(msg: str) -> str:
    return f"{CYAN}  ℹ️  {msg}{RESET}"


# ── Banner & menu ───────────────────────────────────────────────────────────

BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ███████╗ ██████╗ ██████╗  ██████╗ ████████╗███████╗██████╗ ║
║   ██╔════╝██╔════╝██╔═══██╗██╔═══██╗╚══██╔══╝██╔════╝██╔══██╗║
║   ███████╗██║     ██║   ██║██║   ██║   ██║   █████╗  ██████╔╝║
║   ╚════██║██║     ██║   ██║██║   ██║   ██║   ██╔══╝  ██╔══██╗║
║   ███████║╚██████╗╚██████╔╝╚██████╔╝   ██║   ███████╗██║  ██║║
║   ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝║
║                                                              ║
║          BMS DIAGNOSTIC & REPAIR TOOL v0.1.0                 ║
║          Ninebot F2 Pro — "They'll never brick my soul"      ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""


def print_banner() -> None:
    print(f"{BOLD}{CYAN}{BANNER}{RESET}")


def connection_status_line(conn: NinebotConnection) -> str:
    """Return a one-line status string for the current connection."""
    if conn.is_connected and conn.is_authenticated:
        return f"{GREEN}● Connected & Authenticated{RESET}"
    elif conn.is_connected:
        return f"{YELLOW}● Connected (not authenticated){RESET}"
    else:
        return f"{RED}● Disconnected{RESET}"


def print_menu(conn: NinebotConnection) -> None:
    status = connection_status_line(conn)
    print(f"""
  {DIM}Status: {RESET}{status}

{BOLD}─── CONNECTION ─────────────────────────────────{RESET}
  [1]  Scan for scooters
  [2]  Connect & authenticate

{BOLD}─── DIAGNOSTICS ────────────────────────────────{RESET}
  [3]  Full diagnostic report
  [4]  Read cell voltages only
  [5]  Read BMS status flags
  [6]  Read ESC error code
  [7]  Full register dump (0x00-0x50)

{BOLD}─── FIX OPERATIONS ─────────────────────────────{RESET}
  [8]  🔧 Clear charge protection flag
  [9]  🔧 Clear ALL protection flags
  [10] 🔧 Reset SOC calibration
  [11] 🔧 Clear undervolt/overvolt flags
  [12] 🔧 BMS clear error
  [13] ⚠️  ESC reboot
  [14] ⚠️  ESC power off
  [15] 💀 BMS MCU reset (BMS reboots)
  [16] 💀 Flash BMS firmware (NUCLEAR)

{BOLD}─── AUTOMATED ──────────────────────────────────{RESET}
  [17] 🚀 Run full fix sequence (try everything)
  [18] 🔬 Debug: probe ALL writable registers

  [0]  Exit
{DIM}──────────────────────────────────────────────{RESET}""")


# ── Helpers ─────────────────────────────────────────────────────────────────

def require_connection(conn: NinebotConnection) -> None:
    """Raise if the scooter is not connected."""
    if not conn.is_connected:
        raise RuntimeError("Not connected! Use option [2] first.")


def confirm_action(prompt: str) -> bool:
    """Ask for y/N confirmation. Returns True if confirmed."""
    answer = input(f"{YELLOW}  {prompt} (y/N): {RESET}").strip().lower()
    return answer in ("y", "yes")


def confirm_dangerous(action_name: str, keyword: str) -> bool:
    """Require the user to type a specific keyword to proceed."""
    print(warn(f"THIS WILL {action_name}."))
    print(warn("This operation can be destructive and is hard to reverse."))
    answer = input(
        f"{RED}  Type '{keyword}' to confirm, anything else to abort: {RESET}"
    ).strip()
    return answer == keyword


def print_result_tuple(result: tuple[bool, str], success_label: str = "Done") -> None:
    """Pretty-print a (bool, str) result from a BMSCommands method."""
    success, message = result
    if success:
        print(ok(f"{success_label}: {message}"))
    else:
        print(err(f"Failed: {message}"))


# ── Main loop ───────────────────────────────────────────────────────────────

async def main() -> None:
    conn = NinebotConnection()
    diag = BMSDiagnostic(conn)
    cmds = BMSCommands(conn)

    print_banner()

    while True:
        print_menu(conn)

        try:
            choice = input(f"\n  {BOLD}Enter choice:{RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            # Ctrl-D or Ctrl-C at the prompt — treat as exit
            choice = "0"

        try:
            # ── CONNECTION ──────────────────────────────────────────────

            if choice == "1":
                print(info("Scanning for Ninebot scooters..."))
                devices = await scan_for_scooters()
                if not devices:
                    print(warn("No scooters found. Make sure your scooter is on and nearby."))
                else:
                    print(ok(f"Found {len(devices)} scooter(s):"))
                    for d in devices:
                        signal_bar = _rssi_bar(d["rssi"])
                        print(
                            f"    {d['name']}  "
                            f"{DIM}[{d['address']}]{RESET}  "
                            f"RSSI: {d['rssi']} dBm {signal_bar}"
                        )

            elif choice == "2":
                if conn.is_connected:
                    print(warn("Already connected!"))
                    reconnect = confirm_action("Disconnect and reconnect?")
                    if reconnect:
                        await conn.disconnect()
                        print(info("Disconnected."))
                    else:
                        continue

                result = await select_scooter()
                if result:
                    address, device_name = result
                    print(info(f"Connecting to {address}..."))
                    if await conn.connect(address, device_name=device_name):
                        print(ok("Connected!"))
                        print(info("Authenticating..."))
                        if await conn.authenticate():
                            print(ok("Authenticated! Ready to go."))
                        else:
                            print(warn("Authentication failed — connection may still work in unencrypted mode."))
                    else:
                        print(err("Connection failed! Is the scooter powered on?"))
                else:
                    print(warn("No scooter selected."))

            # ── DIAGNOSTICS ─────────────────────────────────────────────

            elif choice == "3":
                require_connection(conn)
                print(info("Running full diagnostic — this may take a few seconds..."))
                await diag.full_diagnostic()
                diag.print_diagnostic()
                print(ok("Diagnostic complete."))

            elif choice == "4":
                require_connection(conn)
                print(info("Reading cell voltages..."))
                voltages = await diag.read_cell_voltages()
                if voltages is None:
                    print(err("Failed to read cell voltages."))
                else:
                    print(ok(f"Read {len(voltages)} cell(s):"))
                    _print_cell_voltages(voltages)

            elif choice == "5":
                require_connection(conn)
                print(info("Reading BMS status flags..."))
                flags = await diag.read_status_flags()
                if flags is None:
                    print(err("Failed to read status flags."))
                else:
                    print(ok("BMS Status Flags:"))
                    _print_flags(flags)

            elif choice == "6":
                require_connection(conn)
                print(info("Reading ESC error code..."))
                error_code = await diag.read_esc_error()
                if error_code is None:
                    print(err("Failed to read ESC error code."))
                elif error_code == 0:
                    print(ok("ESC Error Code: 0 (no error)"))
                else:
                    print(warn(f"ESC Error Code: {error_code} (0x{error_code:04X})"))

            elif choice == "7":
                require_connection(conn)
                print(info("Dumping registers 0x00 — 0x50..."))
                regs = await cmds.register_dump(start=0x00, end=0x50)
                if not regs:
                    print(err("Register dump returned empty."))
                else:
                    print(ok("Register dump:"))
                    _print_register_dump(regs)

            # ── FIX OPERATIONS ──────────────────────────────────────────

            elif choice == "8":
                require_connection(conn)
                if not confirm_action("Clear charge protection flag?"):
                    print(info("Aborted."))
                    continue
                print(info("Clearing charge protection flag..."))
                result = await cmds.clear_charge_protection()
                print_result_tuple(result, "Charge protection cleared")

            elif choice == "9":
                require_connection(conn)
                if not confirm_action("Clear ALL protection flags? This resets every protection bit."):
                    print(info("Aborted."))
                    continue
                print(info("Clearing all protection flags..."))
                result = await cmds.clear_all_protection_flags()
                print_result_tuple(result, "All protection flags cleared")

            elif choice == "10":
                require_connection(conn)
                target_input = input(
                    f"  Target capacity in mAh {DIM}(default 12800){RESET}: "
                ).strip()
                target_cap = 12800
                if target_input:
                    try:
                        target_cap = int(target_input)
                    except ValueError:
                        print(err("Invalid number. Using default 12800 mAh."))
                        target_cap = 12800

                if not confirm_action(f"Reset SOC calibration to {target_cap} mAh?"):
                    print(info("Aborted."))
                    continue
                print(info(f"Resetting SOC calibration (target: {target_cap} mAh)..."))
                result = await cmds.reset_soc_calibration(target_cap=target_cap)
                print_result_tuple(result, "SOC calibration reset")

            elif choice == "11":
                require_connection(conn)
                if not confirm_action("Clear undervolt/overvolt flags?"):
                    print(info("Aborted."))
                    continue
                print(info("Clearing undervolt/overvolt flags..."))
                result = await cmds.clear_undervolt_overvolt()
                print_result_tuple(result, "Undervolt/overvolt flags cleared")

            elif choice == "12":
                require_connection(conn)
                if not confirm_action("Clear BMS error register?"):
                    print(info("Aborted."))
                    continue
                print(info("Clearing BMS error..."))
                result = await cmds.bms_clear_error()
                print_result_tuple(result, "BMS error cleared")

            elif choice == "13":
                require_connection(conn)
                if not confirm_action("Reboot the ESC? The scooter will restart."):
                    print(info("Aborted."))
                    continue
                print(info("Rebooting ESC..."))
                success = await cmds.esc_reboot()
                if success:
                    print(ok("ESC reboot command sent. Scooter should restart."))
                else:
                    print(err("ESC reboot command failed."))

            elif choice == "14":
                require_connection(conn)
                if not confirm_action("Power off the ESC? The scooter will shut down."):
                    print(info("Aborted."))
                    continue
                print(info("Powering off ESC..."))
                success = await cmds.esc_poweroff()
                if success:
                    print(ok("ESC power-off command sent. Scooter should shut down."))
                else:
                    print(err("ESC power-off command failed."))

            elif choice == "15":
                require_connection(conn)
                if not confirm_dangerous("RESET THE BMS MCU", "RESET"):
                    print(info("Aborted."))
                    continue
                print(warn("Resetting BMS MCU — the BMS will reboot..."))
                success = await cmds.bms_mcu_reset()
                if success:
                    print(ok("BMS MCU reset command sent. BMS is rebooting."))
                    print(info("You will need to reconnect after the BMS restarts."))
                else:
                    print(err("BMS MCU reset command failed."))

            elif choice == "16":
                require_connection(conn)
                path = input("  Path to firmware .bin file: ").strip()
                if not path:
                    print(info("No path provided. Aborted."))
                    continue
                if not confirm_dangerous(
                    "FLASH NEW FIRMWARE TO THE BMS", "FLASH"
                ):
                    print(info("Aborted."))
                    continue
                print(warn("Flashing firmware — DO NOT disconnect or power off!"))
                print(info(f"Firmware file: {path}"))
                success = await cmds.flash_firmware(path)
                if success:
                    print(ok("Firmware flash complete!"))
                    print(info("The BMS may reboot. You might need to reconnect."))
                else:
                    print(err("Firmware flash failed!"))

            # ── AUTOMATED ───────────────────────────────────────────────

            elif choice == "17":
                require_connection(conn)
                print(f"""
{YELLOW}{BOLD}  ┌──────────────────────────────────────────────┐
  │  FULL FIX SEQUENCE                            │
  │                                                │
  │  This will attempt every available fix in      │
  │  order. The scooter may reboot multiple times. │
  │                                                │
  │  Steps:                                        │
  │   1. Clear charge protection                   │
  │   2. Clear all protection flags                │
  │   3. Clear undervolt/overvolt                  │
  │   4. BMS clear error                           │
  │   5. Reset SOC calibration                     │
  │   6. ESC reboot                                │
  └──────────────────────────────────────────────┘{RESET}""")
                if not confirm_action("Run the full fix sequence?"):
                    print(info("Aborted."))
                    continue
                print(info("Running full fix sequence..."))
                await cmds.run_fix_sequence()
                print(ok("Full fix sequence complete."))

            elif choice == "18":
                require_connection(conn)
                print(info("Debug: probing writable registers & all fix strategies..."))
                await _debug_probe(conn)

            # ── EXIT ────────────────────────────────────────────────────

            elif choice == "0":
                if conn.is_connected:
                    print(info("Disconnecting..."))
                    await conn.disconnect()
                print(f"\n  {CYAN}Goodbye! May your cells be balanced. ⚡{RESET}\n")
                break

            else:
                print(err(f"Unknown option: '{choice}'. Enter 0–17."))

        except RuntimeError as e:
            print(err(str(e)))
        except KeyboardInterrupt:
            print(warn("Interrupted."))
        except Exception as e:
            print(err(f"Error: {e}"))


# ── Debug probe ────────────────────────────────────────────────────────────

async def _debug_probe(conn: NinebotConnection) -> None:
    """Try every approach to clear OVP and find writable registers."""
    import struct
    from ninebot_bms.protocol import (
        ADDR_PC, ADDR_BMS, ADDR_ESC,
        CMD_WRITE, CMD_WRITE_NO_REPLY, CMD_CLEAR_ERROR,
        build_packet,
    )

    BAT_STATUS = 0x30
    BAT_BALANCE = 0x36
    BAT_UNDERVOLT = 0x37
    BAT_OVERVOLT = 0x38
    BAT_CELL_BASE = 0x40

    async def rd(reg, name=""):
        data = await conn.read_reg(ADDR_BMS, reg, 2)
        if data and len(data) >= 2:
            val = struct.unpack_from("<H", data)[0]
            print(f"    READ 0x{reg:02X} ({name}): 0x{val:04X} ({val})")
            return val
        print(f"    READ 0x{reg:02X} ({name}): FAILED")
        return None

    async def wr(reg, value, name="", reply=True):
        cmd = CMD_WRITE if reply else CMD_WRITE_NO_REPLY
        mode = "CMD_WRITE" if reply else "CMD_WRITE_NO_REPLY"
        pkt = build_packet(ADDR_PC, ADDR_BMS, cmd, reg, struct.pack("<H", value))
        print(f"    WRITE 0x{reg:02X} ({name}) <- 0x{value:04X} [{mode}]")
        if reply:
            resp = await conn.request(pkt, timeout=3.0, retries=1)
            if resp:
                print(f"      -> GOT ACK: cmd=0x{resp['cmd']:02X}")
                return True
            print(f"      -> No ACK")
        else:
            await conn.send_packet(pkt)
            await asyncio.sleep(0.3)
        # Read back
        after = await rd(reg, f"{name} readback")
        if after is not None and after == value:
            print(f"      -> {GREEN}VALUE CHANGED!{RESET}")
            return True
        return False

    print(f"\n{BOLD}═══ PHASE 1: Current state ═══{RESET}")
    status = await rd(BAT_STATUS, "BAT_STATUS")
    await rd(BAT_BALANCE, "BAT_BALANCE")
    await rd(BAT_UNDERVOLT, "BAT_UNDERVOLT")
    await rd(BAT_OVERVOLT, "BAT_OVERVOLT")

    print(f"\n  Cell voltages:")
    cell_data = await conn.read_reg(ADDR_BMS, BAT_CELL_BASE, 20)
    if cell_data and len(cell_data) >= 20:
        for i in range(10):
            mv = struct.unpack_from("<H", cell_data, i * 2)[0]
            flag = " <<<" if mv > 4100 or mv < 3200 else ""
            print(f"    Cell {i+1}: {mv}mV{flag}")

    print(f"\n  Registers 0x31-0x39:")
    for reg in range(0x31, 0x3A):
        await rd(reg, f"reg_0x{reg:02X}")

    print(f"\n{BOLD}═══ PHASE 2: Try force-balancing Cell 9 ═══{RESET}")
    print(f"  Cell 9 = bit 8 → bitmask 0x0100")
    await wr(BAT_BALANCE, 0x0100, "BAT_BALANCE", reply=True)
    await wr(BAT_BALANCE, 0x0100, "BAT_BALANCE", reply=False)

    print(f"\n{BOLD}═══ PHASE 3: Try clearing BAT_OVERVOLT ═══{RESET}")
    await wr(BAT_OVERVOLT, 0x0000, "BAT_OVERVOLT", reply=True)
    await wr(BAT_OVERVOLT, 0x0000, "BAT_OVERVOLT", reply=False)

    print(f"\n{BOLD}═══ PHASE 4: CMD_CLEAR_ERROR to BMS ═══{RESET}")
    pkt = build_packet(ADDR_PC, ADDR_BMS, CMD_CLEAR_ERROR, 0x00)
    print(f"    Sending CMD_CLEAR_ERROR (0x06)...")
    resp = await conn.request(pkt, timeout=3.0, retries=1)
    if resp:
        print(f"    -> Response: cmd=0x{resp['cmd']:02X}")
    else:
        print(f"    -> No ACK, sending no-reply too")
        await conn.send_packet(pkt)
        await asyncio.sleep(0.5)
    await rd(BAT_STATUS, "BAT_STATUS after CLEAR_ERROR")

    print(f"\n{BOLD}═══ PHASE 5: CMD_CLEAR_ERROR to ESC ═══{RESET}")
    pkt = build_packet(ADDR_PC, ADDR_ESC, CMD_CLEAR_ERROR, 0x00)
    print(f"    Sending CMD_CLEAR_ERROR to ESC...")
    resp = await conn.request(pkt, timeout=3.0, retries=1)
    if resp:
        print(f"    -> Response: cmd=0x{resp['cmd']:02X}")
    else:
        print(f"    -> No ACK")

    print(f"\n{BOLD}═══ PHASE 6: Probe writable regs (write 0 to non-zero regs) ═══{RESET}")
    for reg in range(0x31, 0x3A):
        before = await rd(reg, f"0x{reg:02X}")
        if before is not None and before != 0:
            pkt = build_packet(ADDR_PC, ADDR_BMS, CMD_WRITE_NO_REPLY, reg,
                               struct.pack("<H", 0))
            await conn.send_packet(pkt)
            await asyncio.sleep(0.3)
            after = await rd(reg, f"0x{reg:02X} after")
            if after is not None and after != before:
                print(f"    {GREEN}{BOLD}*** 0x{reg:02X} IS WRITABLE! {before} -> {after} ***{RESET}")
            else:
                print(f"    (unchanged)")

    print(f"\n{BOLD}═══ FINAL STATE ═══{RESET}")
    await rd(BAT_STATUS, "BAT_STATUS")
    await rd(BAT_BALANCE, "BAT_BALANCE")
    await rd(BAT_OVERVOLT, "BAT_OVERVOLT")
    print(ok("Debug probe complete."))


# ── Pretty-print helpers ────────────────────────────────────────────────────

def _rssi_bar(rssi: int) -> str:
    """Return a visual signal-strength bar for a given RSSI value."""
    # Typical BLE RSSI range: -100 (weak) to -30 (strong)
    clamped = max(-100, min(-30, rssi))
    bars = int((clamped + 100) / 70 * 5)  # 0..5
    filled = "█" * bars
    empty = "░" * (5 - bars)
    if bars >= 4:
        colour = GREEN
    elif bars >= 2:
        colour = YELLOW
    else:
        colour = RED
    return f"{colour}{filled}{empty}{RESET}"


def _print_cell_voltages(voltages: list[float]) -> None:
    """Pretty-print a list of cell voltages with colour-coded health."""
    if not voltages:
        return

    min_v = min(voltages)
    max_v = max(voltages)
    avg_v = sum(voltages) / len(voltages)
    delta = max_v - min_v

    for i, v in enumerate(voltages, start=1):
        if v < 3.0:
            colour = RED
            tag = " LOW!"
        elif v < 3.3:
            colour = YELLOW
            tag = " low"
        elif v > 4.25:
            colour = RED
            tag = " HIGH!"
        elif v > 4.20:
            colour = YELLOW
            tag = " high"
        else:
            colour = GREEN
            tag = ""
        bar_len = int((v - 2.5) / 2.0 * 20)  # scale 2.5–4.5V to 0–20
        bar_len = max(0, min(20, bar_len))
        bar = "█" * bar_len + "░" * (20 - bar_len)
        print(f"    Cell {i:>2}: {colour}{v:.3f}V{RESET}  {colour}{bar}{RESET}{colour}{tag}{RESET}")

    print()
    if delta > 0.05:
        delta_colour = RED
    elif delta > 0.02:
        delta_colour = YELLOW
    else:
        delta_colour = GREEN
    print(f"    Min: {min_v:.3f}V  Max: {max_v:.3f}V  Avg: {avg_v:.3f}V  "
          f"Delta: {delta_colour}{delta:.3f}V{RESET}")


def _print_flags(flags: dict) -> None:
    """Pretty-print a flags dict with colour-coded True/False values."""
    if not flags:
        return
    max_key_len = max(len(str(k)) for k in flags)
    for key, value in flags.items():
        if isinstance(value, bool):
            colour = RED if value else GREEN
            display = "SET" if value else "clear"
        else:
            colour = CYAN
            display = str(value)
        print(f"    {str(key):<{max_key_len}}  {colour}{display}{RESET}")


def _print_register_dump(regs: dict) -> None:
    """Pretty-print a register dump as a hex table."""
    if not regs:
        return

    # Sort by register address
    sorted_addrs = sorted(regs.keys())
    print(f"    {'Addr':<8} {'Hex':<8} {'Dec':<8} {'Bin'}")
    print(f"    {'─' * 8} {'─' * 8} {'─' * 8} {'─' * 10}")
    for addr in sorted_addrs:
        val = regs[addr]
        if isinstance(val, int):
            hex_str = f"0x{val:04X}"
            dec_str = str(val)
            bin_str = f"{val:016b}"
        else:
            hex_str = str(val)
            dec_str = str(val)
            bin_str = "—"
        addr_str = f"0x{addr:02X}" if isinstance(addr, int) else str(addr)
        print(f"    {DIM}{addr_str:<8}{RESET} {CYAN}{hex_str:<8}{RESET} {dec_str:<8} {DIM}{bin_str}{RESET}")


# ── Entry point ─────────────────────────────────────────────────────────────

def _handle_sigint(conn: NinebotConnection) -> None:
    """Install a SIGINT handler that disconnects gracefully."""
    original_handler = signal.getsignal(signal.SIGINT)

    def handler(sig, frame):
        print(f"\n{YELLOW}  Caught Ctrl+C — disconnecting...{RESET}")
        if conn.is_connected:
            # Schedule disconnect in the running loop
            loop = asyncio.get_event_loop()
            loop.create_task(conn.disconnect())
        print(f"  {CYAN}Goodbye! May your cells be balanced. ⚡{RESET}\n")
        sys.exit(0)

    signal.signal(signal.SIGINT, handler)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n  {CYAN}Goodbye! May your cells be balanced. ⚡{RESET}\n")
        sys.exit(0)
