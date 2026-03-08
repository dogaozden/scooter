"""
BMS write/fix commands for the Ninebot F2 Pro diagnostic tool.

This module contains every write-capable operation, from gentle ESC reboots
to full BMS firmware reflash.  Each method prints exactly what it is doing
(including raw hex packets) so the operator can audit every byte that leaves
the host.

**WARNING** -- These commands can brick the scooter.  The owner has accepted
all risk.
"""

from __future__ import annotations

import asyncio
import struct
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Imports from sibling modules (interface contract)
# ---------------------------------------------------------------------------

from ninebot_bms.protocol import (
    ADDR_ESC,
    ADDR_BMS,
    ADDR_APP,
    ADDR_PC,
    CMD_WRITE,
    CMD_WRITE_NO_REPLY,
    CMD_MCU_RESET,
    CMD_CLEAR_ERROR,
    CMD_IAP_BEGIN,
    CMD_IAP_TRANS,
    CMD_IAP_VERIFY,
    build_packet,
    build_write_cmd,
    build_write_bytes_cmd,
    format_packet_hex,
)

from ninebot_bms.bms import (
    BAT_STATUS,
    BAT_FULL_CAP,
    BAT_DESIGN_CAP,
    BAT_REMAINING_CAP,
    BAT_UNDERVOLT,
    BAT_OVERVOLT,
    BAT_BALANCE,
    BMS_FLAG_CHG_PROTECT,
    BMS_FLAG_WRITE_LOCK,
    BMS_FLAG_CHG_MOS,
    BMS_FLAG_DIS_OVER,
    BMS_FLAG_CHG_OVER,
    BMS_FLAG_OVER_TEMP,
)

# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------

_USE_COLOR = sys.stdout.isatty()


def _red(text: str) -> str:
    return f"\033[91m{text}\033[0m" if _USE_COLOR else text


def _green(text: str) -> str:
    return f"\033[92m{text}\033[0m" if _USE_COLOR else text


def _yellow(text: str) -> str:
    return f"\033[93m{text}\033[0m" if _USE_COLOR else text


def _cyan(text: str) -> str:
    return f"\033[96m{text}\033[0m" if _USE_COLOR else text


def _bold(text: str) -> str:
    return f"\033[1m{text}\033[0m" if _USE_COLOR else text


# ---------------------------------------------------------------------------
# ESC register addresses
# ---------------------------------------------------------------------------

NB_CTL_REBOOT: int = 0x78
NB_CTL_POWEROFF: int = 0x79
NB_CTL_LOCK_ESC: int = 0x70

# ---------------------------------------------------------------------------
# Protection-flag bitmask: bits we want to *clear* during fix operations.
# ---------------------------------------------------------------------------

_PROTECTION_MASK = (
    BMS_FLAG_CHG_PROTECT  # 0x0004
    | BMS_FLAG_DIS_OVER   # 0x0100
    | BMS_FLAG_CHG_OVER   # 0x0200
    | BMS_FLAG_OVER_TEMP  # 0x0400
)

# IAP page size
_IAP_PAGE_SIZE = 128

# ---------------------------------------------------------------------------
# Status-flag decoder
# ---------------------------------------------------------------------------

_STATUS_FLAG_NAMES: dict[int, str] = {
    0x0001: "PASSWORD",
    0x0002: "ACTIVATED",
    BMS_FLAG_CHG_PROTECT: "CHG_PROTECT",
    BMS_FLAG_CHG_MOS: "CHG_MOS",
    BMS_FLAG_WRITE_LOCK: "WRITE_LOCK",
    0x0020: "DISCHARGE",
    0x0040: "CHARGE",
    0x0080: "CHARGER_IN",
    BMS_FLAG_DIS_OVER: "DIS_OVER",
    BMS_FLAG_CHG_OVER: "CHG_OVER",
    BMS_FLAG_OVER_TEMP: "OVER_TEMP",
}


def _decode_status(value: int) -> str:
    """Return a human-readable string of all set status-flag bits."""
    flags: list[str] = []
    for bit, name in sorted(_STATUS_FLAG_NAMES.items()):
        if value & bit:
            flags.append(name)
    unknown = value & ~sum(_STATUS_FLAG_NAMES.keys())
    if unknown:
        flags.append(f"UNK(0x{unknown:04X})")
    return " | ".join(flags) if flags else "(none)"


# ---------------------------------------------------------------------------
# The BMSCommands class
# ---------------------------------------------------------------------------


class BMSCommands:
    """Write / fix commands for the Ninebot F2 Pro BMS.

    Every public method that performs a write prints:
    - a description of the operation
    - the raw hex packet
    - the result (read-back verification where possible)
    """

    def __init__(self, conn):
        self.conn = conn

    # -- helpers ----------------------------------------------------------

    def _print_packet(self, label: str, pkt: bytes) -> None:
        print(f"  {_cyan('TX')} [{label}]: {format_packet_hex(pkt)}")

    async def _read_u16(self, reg: int) -> int | None:
        """Read a single U16 register from the BMS."""
        data = await self.conn.read_reg(ADDR_BMS, reg, 2)
        if data is None or len(data) < 2:
            return None
        return struct.unpack_from("<H", data)[0]

    async def _write_u16(
        self, reg: int, value: int, *, with_reply: bool = True
    ) -> tuple[bool, str]:
        """Write a U16 value to a BMS register and print the packet."""
        pkt = build_write_cmd(ADDR_BMS, reg, value, with_reply=with_reply)
        self._print_packet(f"WRITE BMS 0x{reg:02X} <- 0x{value:04X}", pkt)
        return await self.conn.write_reg(ADDR_BMS, reg, value, with_reply=with_reply)

    async def _write_u16_esc(
        self, reg: int, value: int, *, with_reply: bool = True
    ) -> tuple[bool, str]:
        """Write a U16 value to an ESC register and print the packet."""
        pkt = build_write_cmd(ADDR_ESC, reg, value, with_reply=with_reply)
        self._print_packet(f"WRITE ESC 0x{reg:02X} <- 0x{value:04X}", pkt)
        return await self.conn.write_reg(ADDR_ESC, reg, value, with_reply=with_reply)

    async def _verify_read_back(self, reg: int, expected: int) -> bool:
        """Read a register back and compare to expected value."""
        actual = await self._read_u16(reg)
        if actual is None:
            print(f"  {_yellow('VERIFY')}: read-back of 0x{reg:02X} failed (no response)")
            return False
        if actual == expected:
            print(f"  {_green('VERIFY')}: 0x{reg:02X} == 0x{actual:04X} -- OK")
            return True
        print(
            f"  {_yellow('VERIFY')}: 0x{reg:02X} == 0x{actual:04X} "
            f"(expected 0x{expected:04X}) -- MISMATCH"
        )
        return False

    # ======================================================================
    # 1. ESC reboot
    # ======================================================================

    async def esc_reboot(self) -> bool:
        """Write 0x0001 to ESC register NB_CTL_REBOOT (0x78) to reboot the ESC."""
        print(_bold("\n--- ESC Reboot ---"))
        print(f"  Writing 0x0001 to ESC register 0x{NB_CTL_REBOOT:02X} (NB_CTL_REBOOT)")
        ok, msg = await self._write_u16_esc(NB_CTL_REBOOT, 0x0001)
        if ok:
            print(f"  {_green('OK')}: {msg}")
        else:
            print(f"  {_red('FAIL')}: {msg}")
        return ok

    # ======================================================================
    # 2. ESC power-off
    # ======================================================================

    async def esc_poweroff(self) -> bool:
        """Write 0x0001 to ESC register NB_CTL_POWEROFF (0x79)."""
        print(_bold("\n--- ESC Power-off ---"))
        print(f"  Writing 0x0001 to ESC register 0x{NB_CTL_POWEROFF:02X} (NB_CTL_POWEROFF)")
        print(f"  {_red('WARNING')}: The scooter will power off immediately.")
        ok, msg = await self._write_u16_esc(NB_CTL_POWEROFF, 0x0001)
        if ok:
            print(f"  {_green('OK')}: {msg}")
        else:
            print(f"  {_red('FAIL')}: {msg}")
        return ok

    # ======================================================================
    # 3. Read status raw
    # ======================================================================

    async def read_status_raw(self) -> int | None:
        """Read BAT_STATUS (0x30) and print decoded flags."""
        print(_bold("\n--- Read BAT_STATUS ---"))
        value = await self._read_u16(BAT_STATUS)
        if value is None:
            print(f"  {_red('FAIL')}: could not read BAT_STATUS (0x{BAT_STATUS:02X})")
            return None
        print(f"  BAT_STATUS = 0x{value:04X}  ({value})")
        print(f"  Flags: {_decode_status(value)}")
        return value

    # ======================================================================
    # 4. Clear charge protection
    # ======================================================================

    async def clear_charge_protection(self) -> tuple[bool, str]:
        """Clear CHG_PROTECT and ensure CHG_MOS is set in BAT_STATUS."""
        print(_bold("\n--- Clear Charge Protection ---"))

        status = await self._read_u16(BAT_STATUS)
        if status is None:
            msg = "Could not read BAT_STATUS"
            print(f"  {_red('FAIL')}: {msg}")
            return False, msg

        print(f"  Current BAT_STATUS = 0x{status:04X}  [{_decode_status(status)}]")

        if not (status & BMS_FLAG_CHG_PROTECT):
            msg = "CHG_PROTECT is not set -- nothing to clear"
            print(f"  {_green('INFO')}: {msg}")
            # Still ensure CHG_MOS is on
            if not (status & BMS_FLAG_CHG_MOS):
                print(f"  {_yellow('NOTE')}: CHG_MOS is OFF -- attempting to set it")
                new_val = status | BMS_FLAG_CHG_MOS
                ok, wmsg = await self._write_u16(BAT_STATUS, new_val)
                if ok:
                    await self._verify_read_back(BAT_STATUS, new_val)
                    return True, f"CHG_PROTECT already clear; CHG_MOS set: {wmsg}"
                else:
                    return False, f"CHG_PROTECT already clear; failed to set CHG_MOS: {wmsg}"
            return True, msg

        # Clear CHG_PROTECT, set CHG_MOS
        new_val = (status & ~BMS_FLAG_CHG_PROTECT) | BMS_FLAG_CHG_MOS
        print(
            f"  Target BAT_STATUS = 0x{new_val:04X}  [{_decode_status(new_val)}]"
        )
        print(
            f"  {_red('WARNING')}: Clearing CHG_PROTECT and enabling CHG_MOS "
            f"on BAT_STATUS register 0x{BAT_STATUS:02X}"
        )

        ok, msg = await self._write_u16(BAT_STATUS, new_val)
        if ok:
            print(f"  {_green('OK')}: {msg}")
            await self._verify_read_back(BAT_STATUS, new_val)
            return True, f"Cleared CHG_PROTECT, set CHG_MOS: {msg}"

        # If we got an AUTH error, try enabling write lock first
        if "auth" in msg.lower() or "Authentication" in msg:
            print(f"  {_yellow('AUTH error')} -- trying to enable WRITE_LOCK first...")
            wl_ok, wl_msg = await self.enable_write_lock()
            if wl_ok:
                # Re-read status in case write_lock changed it
                status2 = await self._read_u16(BAT_STATUS)
                if status2 is not None:
                    new_val2 = (status2 & ~BMS_FLAG_CHG_PROTECT) | BMS_FLAG_CHG_MOS
                    ok2, msg2 = await self._write_u16(BAT_STATUS, new_val2)
                    if ok2:
                        print(f"  {_green('OK')}: retry after WRITE_LOCK succeeded: {msg2}")
                        await self._verify_read_back(BAT_STATUS, new_val2)
                        return True, f"Cleared CHG_PROTECT (after WRITE_LOCK): {msg2}"
                    else:
                        return False, f"Retry after WRITE_LOCK still failed: {msg2}"
            return False, f"WRITE_LOCK enable failed ({wl_msg}); original error: {msg}"

        print(f"  {_red('FAIL')}: {msg}")
        return False, msg

    # ======================================================================
    # 5. Enable write lock
    # ======================================================================

    async def enable_write_lock(self) -> tuple[bool, str]:
        """Set the WRITE_LOCK bit (0x0010) in BAT_STATUS."""
        print(_bold("\n--- Enable Write Lock ---"))

        status = await self._read_u16(BAT_STATUS)
        if status is None:
            msg = "Could not read BAT_STATUS"
            print(f"  {_red('FAIL')}: {msg}")
            return False, msg

        print(f"  Current BAT_STATUS = 0x{status:04X}  [{_decode_status(status)}]")

        if status & BMS_FLAG_WRITE_LOCK:
            msg = "WRITE_LOCK already set"
            print(f"  {_green('INFO')}: {msg}")
            return True, msg

        new_val = status | BMS_FLAG_WRITE_LOCK
        print(f"  Target BAT_STATUS = 0x{new_val:04X}  [{_decode_status(new_val)}]")
        print(
            f"  {_yellow('CAUTION')}: Setting WRITE_LOCK bit on BAT_STATUS "
            f"register 0x{BAT_STATUS:02X}"
        )

        ok, msg = await self._write_u16(BAT_STATUS, new_val)
        if ok:
            print(f"  {_green('OK')}: {msg}")
            await self._verify_read_back(BAT_STATUS, new_val)
        else:
            print(f"  {_red('FAIL')}: {msg}")
        return ok, msg

    # ======================================================================
    # 6. Clear all protection flags
    # ======================================================================

    async def clear_all_protection_flags(self) -> tuple[bool, str]:
        """Clear every protection bit while keeping safe operational bits.

        Tries multiple strategies:
          1. CMD_WRITE (0x02) — standard write with ACK
          2. CMD_WRITE_NO_REPLY (0x03) — fire-and-forget + readback
          3. CMD_CLEAR_ERROR (0x06) — protocol-level error clear
          4. Enable WRITE_LOCK first, then retry
        """
        print(_bold("\n--- Clear ALL Protection Flags ---"))

        status = await self._read_u16(BAT_STATUS)
        if status is None:
            msg = "Could not read BAT_STATUS"
            print(f"  {_red('FAIL')}: {msg}")
            return False, msg

        print(f"  Current BAT_STATUS = 0x{status:04X}  [{_decode_status(status)}]")

        active_protections = status & _PROTECTION_MASK
        if not active_protections:
            msg = "No protection flags are set"
            print(f"  {_green('INFO')}: {msg}")
            return True, msg

        # Print which protection bits are active
        for bit, name in _STATUS_FLAG_NAMES.items():
            if active_protections & bit:
                print(f"  {_red('ACTIVE')}: {name} (0x{bit:04X})")

        new_val = status & ~_PROTECTION_MASK
        print(f"  Target BAT_STATUS = 0x{new_val:04X}  [{_decode_status(new_val)}]")

        # --- Strategy 1: CMD_WRITE (with ACK) ---
        print(f"\n  {_cyan('Strategy 1')}: CMD_WRITE (0x02) with ACK...")
        ok, msg = await self._write_u16(BAT_STATUS, new_val)
        if ok:
            print(f"  {_green('OK')}: {msg}")
            await self._verify_read_back(BAT_STATUS, new_val)
            return True, f"Cleared via CMD_WRITE: {msg}"

        print(f"  {_yellow('MISS')}: {msg}")

        # Check if the write went through silently (some BMS don't ACK)
        status_after = await self._read_u16(BAT_STATUS)
        if status_after is not None and (status_after & _PROTECTION_MASK) == 0:
            msg = "Write went through silently (no ACK but value changed)"
            print(f"  {_green('OK')}: {msg}")
            print(f"  BAT_STATUS now = 0x{status_after:04X}  [{_decode_status(status_after)}]")
            return True, msg

        # --- Strategy 2: CMD_WRITE_NO_REPLY (fire-and-forget) ---
        print(f"\n  {_cyan('Strategy 2')}: CMD_WRITE_NO_REPLY (0x03)...")
        pkt = build_write_cmd(ADDR_BMS, BAT_STATUS, new_val, with_reply=False)
        self._print_packet(f"WRITE_NO_REPLY BMS 0x{BAT_STATUS:02X} <- 0x{new_val:04X}", pkt)
        await self.conn.send_packet(pkt)
        await asyncio.sleep(0.5)

        status_after = await self._read_u16(BAT_STATUS)
        if status_after is not None and (status_after & _PROTECTION_MASK) == 0:
            msg = f"Cleared via CMD_WRITE_NO_REPLY (BAT_STATUS now 0x{status_after:04X})"
            print(f"  {_green('OK')}: {msg}")
            return True, msg
        if status_after is not None:
            print(f"  {_yellow('MISS')}: BAT_STATUS still 0x{status_after:04X}")
        else:
            print(f"  {_yellow('MISS')}: Could not read back BAT_STATUS")

        # --- Strategy 3: CMD_CLEAR_ERROR ---
        print(f"\n  {_cyan('Strategy 3')}: CMD_CLEAR_ERROR (0x06)...")
        pkt_clr = build_packet(ADDR_PC, ADDR_BMS, CMD_CLEAR_ERROR, 0x00)
        self._print_packet("CLEAR_ERROR -> BMS", pkt_clr)
        resp = await self.conn.request(pkt_clr, timeout=3.0, retries=2)
        if resp is not None:
            print(f"  Got response: cmd=0x{resp.get('cmd', 0):02X}")
        else:
            # Try no-reply version
            await self.conn.send_packet(pkt_clr)
            await asyncio.sleep(0.5)

        status_after = await self._read_u16(BAT_STATUS)
        if status_after is not None and (status_after & _PROTECTION_MASK) == 0:
            msg = f"Cleared via CMD_CLEAR_ERROR (BAT_STATUS now 0x{status_after:04X})"
            print(f"  {_green('OK')}: {msg}")
            return True, msg
        if status_after is not None:
            print(f"  {_yellow('MISS')}: BAT_STATUS still 0x{status_after:04X}")

        # --- Strategy 4: Enable WRITE_LOCK, then retry ---
        print(f"\n  {_cyan('Strategy 4')}: Enable WRITE_LOCK then CMD_WRITE...")
        # Read fresh status
        status = await self._read_u16(BAT_STATUS)
        if status is not None and not (status & BMS_FLAG_WRITE_LOCK):
            wl_val = status | BMS_FLAG_WRITE_LOCK
            print(f"  Setting WRITE_LOCK: 0x{status:04X} -> 0x{wl_val:04X}")
            # Try both write modes for WRITE_LOCK itself
            await self._write_u16(BAT_STATUS, wl_val)
            await asyncio.sleep(0.3)
            pkt_wl = build_write_cmd(ADDR_BMS, BAT_STATUS, wl_val, with_reply=False)
            await self.conn.send_packet(pkt_wl)
            await asyncio.sleep(0.5)

            # Now try clearing protections again
            status = await self._read_u16(BAT_STATUS)
            if status is not None:
                print(f"  BAT_STATUS after WRITE_LOCK attempt: 0x{status:04X}")
                new_val = status & ~_PROTECTION_MASK
                ok, msg = await self._write_u16(BAT_STATUS, new_val)
                if ok:
                    print(f"  {_green('OK')}: {msg}")
                    return True, f"Cleared via WRITE_LOCK + CMD_WRITE: {msg}"
                # Check silent write
                status_after = await self._read_u16(BAT_STATUS)
                if status_after is not None and (status_after & _PROTECTION_MASK) == 0:
                    msg = f"Cleared after WRITE_LOCK (BAT_STATUS now 0x{status_after:04X})"
                    print(f"  {_green('OK')}: {msg}")
                    return True, msg

        # All strategies failed
        status_final = await self._read_u16(BAT_STATUS)
        final_hex = f"0x{status_final:04X}" if status_final is not None else "N/A"
        msg = f"All 4 strategies failed. BAT_STATUS = {final_hex}"
        print(f"\n  {_red('FAIL')}: {msg}")
        return False, msg

    # ======================================================================
    # 7. Reset SOC calibration
    # ======================================================================

    async def reset_soc_calibration(
        self, target_cap: int = 12800
    ) -> tuple[bool, str]:
        """Align BAT_FULL_CAP to *target_cap* and fix BAT_REMAINING_CAP."""
        print(_bold("\n--- Reset SOC Calibration ---"))

        design = await self._read_u16(BAT_DESIGN_CAP)
        full = await self._read_u16(BAT_FULL_CAP)
        remaining = await self._read_u16(BAT_REMAINING_CAP)

        print(f"  BAT_DESIGN_CAP    (0x{BAT_DESIGN_CAP:02X}) = {design}")
        print(f"  BAT_FULL_CAP      (0x{BAT_FULL_CAP:02X}) = {full}")
        print(f"  BAT_REMAINING_CAP (0x{BAT_REMAINING_CAP:02X}) = {remaining}")

        results: list[str] = []
        any_ok = False

        # -- fix full capacity ------------------------------------------------
        if full is not None and full != target_cap:
            print(
                f"  {_yellow('CAUTION')}: Writing BAT_FULL_CAP = {target_cap} "
                f"(was {full})"
            )
            ok, msg = await self._write_u16(BAT_FULL_CAP, target_cap)
            if ok:
                print(f"  {_green('OK')}: BAT_FULL_CAP write: {msg}")
                await self._verify_read_back(BAT_FULL_CAP, target_cap)
                any_ok = True
            else:
                print(f"  {_red('FAIL')}: BAT_FULL_CAP write: {msg}")
            results.append(f"FULL_CAP {full}->{target_cap}: {msg}")
        elif full == target_cap:
            results.append(f"FULL_CAP already {target_cap}")
            any_ok = True
        else:
            results.append("FULL_CAP read failed")

        # -- fix remaining capacity -------------------------------------------
        # Estimate a sensible remaining-cap value.  If we can read cell
        # voltages (reg 0x40-0x49) we could do better, but a simple heuristic
        # is: assume ~50 % SoC (gives the BMS room to recalibrate on next
        # full charge cycle).
        estimated_remaining = target_cap // 2
        if remaining is not None and remaining != estimated_remaining:
            print(
                f"  {_yellow('CAUTION')}: Writing BAT_REMAINING_CAP = "
                f"{estimated_remaining} (was {remaining})"
            )
            ok, msg = await self._write_u16(BAT_REMAINING_CAP, estimated_remaining)
            if ok:
                print(f"  {_green('OK')}: BAT_REMAINING_CAP write: {msg}")
                await self._verify_read_back(BAT_REMAINING_CAP, estimated_remaining)
                any_ok = True
            else:
                print(f"  {_red('FAIL')}: BAT_REMAINING_CAP write: {msg}")
            results.append(
                f"REMAINING_CAP {remaining}->{estimated_remaining}: {msg}"
            )
        elif remaining == estimated_remaining:
            results.append(f"REMAINING_CAP already {estimated_remaining}")
        else:
            results.append("REMAINING_CAP read failed")

        summary = "; ".join(results)
        return any_ok, summary

    # ======================================================================
    # 8. Clear undervolt / overvolt bitmaps
    # ======================================================================

    async def clear_undervolt_overvolt(self) -> tuple[bool, str]:
        """Write 0x0000 to BAT_UNDERVOLT and BAT_OVERVOLT fault bitmaps."""
        print(_bold("\n--- Clear Undervolt / Overvolt Bitmaps ---"))

        # Read current values first
        uv = await self._read_u16(BAT_UNDERVOLT)
        ov = await self._read_u16(BAT_OVERVOLT)
        print(f"  BAT_UNDERVOLT (0x{BAT_UNDERVOLT:02X}) = {f'0x{uv:04X}' if uv is not None else 'N/A'}")
        print(f"  BAT_OVERVOLT  (0x{BAT_OVERVOLT:02X}) = {f'0x{ov:04X}' if ov is not None else 'N/A'}")

        results: list[str] = []
        any_ok = False

        # Clear undervolt
        print(
            f"  {_red('WARNING')}: Writing 0x0000 to BAT_UNDERVOLT "
            f"(0x{BAT_UNDERVOLT:02X})"
        )
        ok1, msg1 = await self._write_u16(BAT_UNDERVOLT, 0x0000)
        if ok1:
            print(f"  {_green('OK')}: BAT_UNDERVOLT cleared: {msg1}")
            await self._verify_read_back(BAT_UNDERVOLT, 0x0000)
            any_ok = True
        else:
            print(f"  {_red('FAIL')}: BAT_UNDERVOLT: {msg1}")
        results.append(f"UNDERVOLT: {msg1}")

        # Clear overvolt
        print(
            f"  {_red('WARNING')}: Writing 0x0000 to BAT_OVERVOLT "
            f"(0x{BAT_OVERVOLT:02X})"
        )
        ok2, msg2 = await self._write_u16(BAT_OVERVOLT, 0x0000)
        if ok2:
            print(f"  {_green('OK')}: BAT_OVERVOLT cleared: {msg2}")
            await self._verify_read_back(BAT_OVERVOLT, 0x0000)
            any_ok = True
        else:
            print(f"  {_red('FAIL')}: BAT_OVERVOLT: {msg2}")
        results.append(f"OVERVOLT: {msg2}")

        return any_ok, "; ".join(results)

    # ======================================================================
    # 9. BMS MCU reset
    # ======================================================================

    async def bms_mcu_reset(self) -> bool:
        """Send CMD_MCU_RESET (0x0A) to the BMS -- it will reboot."""
        print(_bold("\n--- BMS MCU Reset ---"))
        print(
            f"  {_red('WARNING')}: Sending MCU reset to BMS (0x{ADDR_BMS:02X}). "
            f"The BLE connection WILL drop."
        )

        pkt = build_packet(ADDR_PC, ADDR_BMS, CMD_MCU_RESET, 0x00)
        self._print_packet("MCU_RESET -> BMS", pkt)

        await self.conn.send_packet(pkt)
        print(f"  {_yellow('SENT')}: Waiting 2 seconds for BMS to reboot...")
        await asyncio.sleep(2)
        print(
            f"  {_green('DONE')}: MCU reset sent. "
            f"Reconnection required to continue."
        )
        return True

    # ======================================================================
    # 10. BMS clear error
    # ======================================================================

    async def bms_clear_error(self) -> tuple[bool, str]:
        """Send CMD_CLEAR_ERROR (0x06) to the BMS."""
        print(_bold("\n--- BMS Clear Error ---"))

        pkt = build_packet(ADDR_PC, ADDR_BMS, CMD_CLEAR_ERROR, 0x00)
        self._print_packet("CLEAR_ERROR -> BMS", pkt)

        resp = await self.conn.request(pkt, timeout=3.0, retries=2)
        if resp is None:
            msg = "No response to CLEAR_ERROR (may still have worked)"
            print(f"  {_yellow('WARN')}: {msg}")
            return False, msg

        # If we got any response at all, treat it as success
        msg = f"BMS responded to CLEAR_ERROR (cmd=0x{resp.get('cmd', 0):02X})"
        print(f"  {_green('OK')}: {msg}")
        return True, msg

    # ======================================================================
    # 11. Flash firmware
    # ======================================================================

    async def flash_firmware(self, firmware_path: str) -> bool:
        """Flash a firmware binary to the BMS via IAP protocol.

        Steps:
          1. Lock ESC (write 0x0001 to ESC 0x70)
          2. CMD_IAP_BEGIN with firmware size
          3. CMD_IAP_TRANS -- send 128-byte pages
          4. CMD_IAP_VERIFY with ones-complement checksum
          5. CMD_MCU_RESET to reboot
        """
        print(_bold("\n--- Flash BMS Firmware ---"))
        print(f"  {_red('!!! EXTREME DANGER !!!')}")
        print(f"  {_red('This WILL brick the scooter if the firmware is wrong.')}")
        print(f"  Firmware file: {firmware_path}")

        # -- Read firmware file -----------------------------------------------
        fw_path = Path(firmware_path)
        if not fw_path.is_file():
            print(f"  {_red('FAIL')}: Firmware file not found: {firmware_path}")
            return False

        fw_data = fw_path.read_bytes()
        fw_size = len(fw_data)
        print(f"  Firmware size: {fw_size} bytes ({fw_size:#x})")

        if fw_size == 0:
            print(f"  {_red('FAIL')}: Firmware file is empty")
            return False

        # -- Step 1: Lock ESC -------------------------------------------------
        print(f"\n  {_yellow('Step 1/5')}: Locking ESC...")
        ok, msg = await self._write_u16_esc(NB_CTL_LOCK_ESC, 0x0001)
        if not ok:
            print(f"  {_red('FAIL')}: Could not lock ESC: {msg}")
            return False
        print(f"  {_green('OK')}: ESC locked")

        # -- Step 2: IAP_BEGIN ------------------------------------------------
        print(f"\n  {_yellow('Step 2/5')}: Sending IAP_BEGIN (size={fw_size})...")
        size_data = struct.pack("<I", fw_size)
        pkt_begin = build_packet(ADDR_PC, ADDR_BMS, CMD_IAP_BEGIN, 0x00, size_data)
        self._print_packet("IAP_BEGIN", pkt_begin)

        resp = await self.conn.request(pkt_begin, timeout=5.0, retries=2)
        if resp is None:
            print(f"  {_red('FAIL')}: No response to IAP_BEGIN")
            return False
        print(f"  {_green('OK')}: BMS acknowledged IAP_BEGIN")

        # -- Step 3: IAP_TRANS (page-by-page) ---------------------------------
        total_pages = (fw_size + _IAP_PAGE_SIZE - 1) // _IAP_PAGE_SIZE
        print(
            f"\n  {_yellow('Step 3/5')}: Sending {total_pages} pages "
            f"({_IAP_PAGE_SIZE} bytes each)..."
        )

        for page_num in range(total_pages):
            offset = page_num * _IAP_PAGE_SIZE
            chunk = fw_data[offset : offset + _IAP_PAGE_SIZE]

            pkt_page = build_packet(
                ADDR_APP,
    ADDR_PC, ADDR_BMS, CMD_IAP_TRANS, page_num & 0xFF, chunk
            )

            resp = await self.conn.request(pkt_page, timeout=5.0, retries=3)
            if resp is None:
                print(
                    f"\n  {_red('FAIL')}: No ACK for page {page_num}/{total_pages}"
                )
                return False

            # Progress bar
            pct = (page_num + 1) * 100 // total_pages
            bar_len = 40
            filled = bar_len * (page_num + 1) // total_pages
            bar = "#" * filled + "-" * (bar_len - filled)
            sys.stdout.write(
                f"\r  [{bar}] {pct:3d}% "
                f"(page {page_num + 1}/{total_pages})"
            )
            sys.stdout.flush()

        print()  # newline after progress bar
        print(f"  {_green('OK')}: All {total_pages} pages sent")

        # -- Step 4: IAP_VERIFY -----------------------------------------------
        print(f"\n  {_yellow('Step 4/5')}: Sending IAP_VERIFY...")
        fw_sum = sum(fw_data) & 0xFFFFFFFF
        checksum = (~fw_sum) & 0xFFFFFFFF
        chk_data = struct.pack("<I", checksum)
        print(
            f"  Firmware sum = 0x{fw_sum:08X}, "
            f"checksum (ones-complement) = 0x{checksum:08X}"
        )

        pkt_verify = build_packet(
            ADDR_APP,
    ADDR_PC, ADDR_BMS, CMD_IAP_VERIFY, 0x00, chk_data
        )
        self._print_packet("IAP_VERIFY", pkt_verify)

        resp = await self.conn.request(pkt_verify, timeout=10.0, retries=2)
        if resp is None:
            print(f"  {_red('FAIL')}: No response to IAP_VERIFY")
            return False
        print(f"  {_green('OK')}: BMS verified firmware checksum")

        # -- Step 5: MCU_RESET ------------------------------------------------
        print(f"\n  {_yellow('Step 5/5')}: Rebooting BMS...")
        pkt_reset = build_packet(ADDR_PC, ADDR_BMS, CMD_MCU_RESET, 0x00)
        self._print_packet("MCU_RESET", pkt_reset)
        await self.conn.send_packet(pkt_reset)
        await asyncio.sleep(2)

        print(f"  {_green('DONE')}: Firmware flash complete. BMS is rebooting.")
        print(
            f"  {_yellow('NOTE')}: Reconnect after ~10 seconds to verify "
            f"the new firmware."
        )
        return True

    # ======================================================================
    # 12. Register dump
    # ======================================================================

    async def register_dump(
        self, start: int = 0x00, end: int = 0x50
    ) -> dict[int, int]:
        """Read all BMS registers from *start* to *end* and print a hex table."""
        print(_bold(f"\n--- BMS Register Dump (0x{start:02X}..0x{end:02X}) ---"))

        regs: dict[int, int] = {}
        addr = start

        while addr < end:
            # Read 16 bytes = 8 U16 registers at a time
            chunk_bytes = min(16, (end - addr) * 2)
            data = await self.conn.read_reg(ADDR_BMS, addr, chunk_bytes)

            if data is None:
                # Fill with sentinel values
                for i in range(chunk_bytes // 2):
                    regs[addr + i] = 0xDEAD  # sentinel for read failure
                addr += chunk_bytes // 2
                continue

            # Unpack however many U16 values we got
            n_regs = len(data) // 2
            for i in range(n_regs):
                val = struct.unpack_from("<H", data, i * 2)[0]
                regs[addr + i] = val
            addr += n_regs

        # -- Print hex dump table ---------------------------------------------
        print()
        print(f"  {'REG':>5s}  {'HEX':>6s}  {'DEC':>6s}  {'NOTE'}")
        print(f"  {'-----':>5s}  {'------':>6s}  {'------':>6s}  {'----'}")

        for reg_addr in sorted(regs.keys()):
            val = regs[reg_addr]
            note = ""
            if val == 0xDEAD:
                note = _red("READ FAILED")
            elif 2500 <= val <= 4250:
                note = _cyan(f"<-- cell voltage? ({val} mV)")
            elif reg_addr == BAT_STATUS:
                note = _yellow(f"STATUS: {_decode_status(val)}")
            elif reg_addr == BAT_FULL_CAP:
                note = f"FULL_CAP ({val} mAh)"
            elif reg_addr == BAT_DESIGN_CAP:
                note = f"DESIGN_CAP ({val} mAh)"
            elif reg_addr == BAT_REMAINING_CAP:
                note = f"REMAINING_CAP ({val} mAh)"
            elif reg_addr == BAT_UNDERVOLT:
                note = f"UNDERVOLT bitmap (0x{val:04X})"
            elif reg_addr == BAT_OVERVOLT:
                note = f"OVERVOLT bitmap (0x{val:04X})"

            if val == 0xDEAD:
                val_hex = " DEAD"
                val_dec = "     ?"
            else:
                val_hex = f"0x{val:04X}"
                val_dec = f"{val:6d}"

            print(f"  0x{reg_addr:02X}   {val_hex}  {val_dec}  {note}")

        print()
        return regs

    # ======================================================================
    # 13. Automated fix sequence
    # ======================================================================

    async def run_fix_sequence(self) -> None:
        """Try everything, step by step, with user confirmation."""
        print(_bold("\n" + "=" * 60))
        print(_bold("  NINEBOT F2 PRO BMS -- AUTOMATED FIX SEQUENCE"))
        print(_bold("=" * 60))
        print()
        print(f"  {_red('WARNING')}: This sequence will attempt multiple write")
        print(f"  operations on the BMS.  The owner has accepted all risk")
        print(f"  including full brick.")
        print()

        # -- Step 1: register dump (before) -----------------------------------
        print(_bold("Step 1/10: Full register dump (BEFORE)"))
        before = await self.register_dump()

        # -- Step 2: clear charge protection ----------------------------------
        print(_bold("\nStep 2/10: Clear charge protection"))
        input("  Press Enter to continue or Ctrl+C to abort: ")
        ok2, msg2 = await self.clear_charge_protection()
        print(f"  Result: {msg2}")

        # -- Step 3: clear all protection flags --------------------------------
        print(_bold("\nStep 3/10: Clear ALL protection flags"))
        input("  Press Enter to continue or Ctrl+C to abort: ")
        ok3, msg3 = await self.clear_all_protection_flags()
        print(f"  Result: {msg3}")

        # -- Step 4: clear undervolt/overvolt ----------------------------------
        print(_bold("\nStep 4/10: Clear undervolt/overvolt bitmaps"))
        input("  Press Enter to continue or Ctrl+C to abort: ")
        ok4, msg4 = await self.clear_undervolt_overvolt()
        print(f"  Result: {msg4}")

        # -- Step 5: reset SOC calibration ------------------------------------
        print(_bold("\nStep 5/10: Reset SOC calibration"))
        input("  Press Enter to continue or Ctrl+C to abort: ")
        ok5, msg5 = await self.reset_soc_calibration()
        print(f"  Result: {msg5}")

        # -- Step 6: BMS clear error ------------------------------------------
        print(_bold("\nStep 6/10: BMS clear error"))
        input("  Press Enter to continue or Ctrl+C to abort: ")
        ok6, msg6 = await self.bms_clear_error()
        print(f"  Result: {msg6}")

        # -- Step 7: register dump (after) ------------------------------------
        print(_bold("\nStep 7/10: Full register dump (AFTER)"))
        after = await self.register_dump()

        # -- Step 8: compare before / after ------------------------------------
        print(_bold("\nStep 8/10: Compare BEFORE vs AFTER"))
        changes_found = False
        for reg_addr in sorted(set(before.keys()) | set(after.keys())):
            val_before = before.get(reg_addr)
            val_after = after.get(reg_addr)
            if val_before != val_after:
                changes_found = True
                b_str = f"0x{val_before:04X}" if val_before is not None else "N/A"
                a_str = f"0x{val_after:04X}" if val_after is not None else "N/A"
                print(
                    f"  {_green('CHANGED')}: reg 0x{reg_addr:02X}  "
                    f"{b_str} -> {a_str}"
                )

        if not changes_found:
            print(f"  {_yellow('No register changes detected.')}")

        # -- Step 9: offer MCU reset ------------------------------------------
        print(_bold("\nStep 9/10: BMS MCU Reset"))
        if not changes_found:
            print(f"  {_yellow('Nothing changed so far.')}")
        print(f"  {_red('WARNING')}: This will reboot the BMS. Connection will drop.")
        try:
            answer = input("  Send MCU reset? (y/N): ").strip().lower()
            if answer == "y":
                await self.bms_mcu_reset()
            else:
                print("  Skipped MCU reset.")
        except (EOFError, KeyboardInterrupt):
            print("\n  Skipped MCU reset.")

        # -- Step 10: offer firmware flash ------------------------------------
        print(_bold("\nStep 10/10: Firmware Flash"))
        print(f"  {_red('!!! LAST RESORT -- EXTREME DANGER !!!')}")
        try:
            answer = input(
                "  Do you want to flash firmware? (y/N): "
            ).strip().lower()
            if answer == "y":
                fw_path = input("  Enter firmware file path: ").strip()
                if fw_path:
                    input(
                        f"  {_red('FINAL WARNING')}: About to flash "
                        f"'{fw_path}'. Press Enter to proceed or Ctrl+C to abort: "
                    )
                    result = await self.flash_firmware(fw_path)
                    if result:
                        print(f"  {_green('Firmware flash completed.')}")
                    else:
                        print(f"  {_red('Firmware flash FAILED.')}")
                else:
                    print("  No path provided. Skipped.")
            else:
                print("  Skipped firmware flash.")
        except (EOFError, KeyboardInterrupt):
            print("\n  Skipped firmware flash.")

        print(_bold("\n" + "=" * 60))
        print(_bold("  FIX SEQUENCE COMPLETE"))
        print(_bold("=" * 60))
