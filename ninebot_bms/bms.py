"""
Ninebot F2 Pro BMS register layer and diagnostic engine.

Provides the BMSDiagnostic class that reads all BMS registers via a
NinebotConnection, decodes them into human-readable values, and prints
a comprehensive diagnostic report with fault analysis.
"""

from __future__ import annotations

import struct

from ninebot_bms.protocol import ADDR_BMS, ADDR_ESC

# ---------------------------------------------------------------------------
# BMS Register Map — Identity Registers
# ---------------------------------------------------------------------------

BAT_SN = 0x10              # 7 words (14 bytes) - serial number
BAT_FW_VER = 0x17          # U16 - firmware version
BAT_DESIGN_CAP = 0x18      # U16 - design capacity mAh
BAT_FULL_CAP = 0x19        # U16 - full charge capacity mAh
BAT_DESIGN_VOLT = 0x1A     # U16 - design voltage, 10mV units
BAT_CYCLE_TIMES = 0x1B     # U16 - charge cycle count
BAT_CHARGE_TIMES = 0x1C    # U16 - total charge count
BAT_CHARGE_CAP_L = 0x1D    # U16 - accumulated charge capacity low, 10mAh
BAT_CHARGE_CAP_H = 0x1E    # U16 - accumulated charge capacity high, 10mAh
BAT_OVER_DIS_TIMES = 0x1F  # U16 - low byte: overflow count, high byte: over-discharge count

# ---------------------------------------------------------------------------
# BMS Register Map — Status Registers
# ---------------------------------------------------------------------------

BAT_STATUS = 0x30           # S16 - boolean status flags
BAT_REMAINING_CAP = 0x31    # U16 - remaining capacity mAh
BAT_REMAINING_PCT = 0x32    # S16 - remaining percentage 0-100
BAT_CURRENT = 0x33          # S16 - current in 10mA (positive=discharge, negative=charge)
BAT_VOLTAGE = 0x34          # S16 - voltage in 10mV
BAT_TEMP = 0x35             # S16 - low byte: temp1, high byte: temp2 (value - 20 = deg C)
BAT_BALANCE = 0x36          # S16 - cell balancing bitmap
BAT_UNDERVOLT = 0x37        # S16 - cell undervoltage bitmap
BAT_OVERVOLT = 0x38         # S16 - cell overvoltage bitmap
BAT_COULOMB_CAP = 0x39      # S16 - coulomb counter capacity
BAT_VOLT_CAP = 0x3A         # S16 - voltage-based capacity
BAT_HEALTH = 0x3B           # S16 - health percentage 0-100

# ---------------------------------------------------------------------------
# BMS Register Map — Cell Voltage Registers
# ---------------------------------------------------------------------------

BAT_CELL_BASE = 0x40        # First cell voltage register
# 0x40-0x49 = cells 1-10, each U16 in mV
NUM_CELLS = 10

# ---------------------------------------------------------------------------
# Status Flag Bits (for register 0x30)
# ---------------------------------------------------------------------------

BMS_FLAG_PASSWORD    = 0x0001  # Password check passed
BMS_FLAG_ACTIVATED   = 0x0002  # Battery activated
BMS_FLAG_CHG_PROTECT = 0x0004  # Charge protection ACTIVE
BMS_FLAG_CHG_MOS     = 0x0008  # Charge MOSFET open
BMS_FLAG_WRITE_LOCK  = 0x0010  # Write lock open (needed for writes)
BMS_FLAG_DISCHARGING = 0x0020  # Currently discharging
BMS_FLAG_CHARGING    = 0x0040  # Currently charging
BMS_FLAG_CHARGER_IN  = 0x0080  # Charger plugged in
BMS_FLAG_DIS_OVER    = 0x0100  # Over-discharge protection
BMS_FLAG_CHG_OVER    = 0x0200  # Over-charge protection
BMS_FLAG_OVER_TEMP   = 0x0400  # Over-temperature
BMS_FLAG_TEST_MODE   = 0x0800  # Test mode

# Ordered mapping for iteration and display
_FLAG_DEFS: list[tuple[int, str, str]] = [
    (BMS_FLAG_PASSWORD,    "password",    "Password Check Passed"),
    (BMS_FLAG_ACTIVATED,   "activated",   "Battery Activated"),
    (BMS_FLAG_CHG_PROTECT, "chg_protect", "Charge Protection ACTIVE"),
    (BMS_FLAG_CHG_MOS,     "chg_mos",     "Charge MOSFET Open"),
    (BMS_FLAG_WRITE_LOCK,  "write_lock",  "Write Lock Open"),
    (BMS_FLAG_DISCHARGING, "discharging", "Currently Discharging"),
    (BMS_FLAG_CHARGING,    "charging",    "Currently Charging"),
    (BMS_FLAG_CHARGER_IN,  "charger_in",  "Charger Plugged In"),
    (BMS_FLAG_DIS_OVER,    "dis_over",    "Over-Discharge Protection"),
    (BMS_FLAG_CHG_OVER,    "chg_over",    "Over-Charge Protection"),
    (BMS_FLAG_OVER_TEMP,   "over_temp",   "Over-Temperature"),
    (BMS_FLAG_TEST_MODE,   "test_mode",   "Test Mode"),
]

# Flags that indicate a fault / warning condition
_WARN_FLAGS = {BMS_FLAG_CHG_PROTECT, BMS_FLAG_DIS_OVER, BMS_FLAG_CHG_OVER, BMS_FLAG_OVER_TEMP}

# ---------------------------------------------------------------------------
# ESC Registers (cross-reference, read from ADDR_ESC)
# ---------------------------------------------------------------------------

ESC_ERROR = 0x1B            # Error code
ESC_BMS_FW_VER = 0x67       # BMS firmware version as seen by ESC

# Known BMS-related ESC error codes
_ESC_ERROR_MAP: dict[int, str] = {
    16: "Battery MOS switch abnormality",
    21: "No communication with BMS",
    22: "BMS config invalid",
    23: "BMS not activated",
    45: "Deep cell discharge",
    47: "Battery protection board damaged",
    49: "BMS firmware version mismatch",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _u16(data: bytes, offset: int = 0) -> int:
    """Read an unsigned 16-bit little-endian value from *data* at *offset*."""
    return struct.unpack_from("<H", data, offset)[0]


def _s16(data: bytes, offset: int = 0) -> int:
    """Read a signed 16-bit little-endian value from *data* at *offset*."""
    return struct.unpack_from("<h", data, offset)[0]


def _decode_bitmap(value: int, num_bits: int = NUM_CELLS) -> list[int]:
    """Return a list of 1-based cell indices whose bits are set in *value*."""
    return [i + 1 for i in range(num_bits) if value & (1 << i)]


# ---------------------------------------------------------------------------
# BMSDiagnostic
# ---------------------------------------------------------------------------


class BMSDiagnostic:
    """High-level reader and diagnostic reporter for the Ninebot F2 Pro BMS.

    Parameters
    ----------
    conn:
        A ``NinebotConnection`` instance providing ``read_reg`` and
        ``write_reg`` coroutines.
    """

    def __init__(self, conn) -> None:
        self.conn = conn
        self.data: dict = {}

    # ------------------------------------------------------------------
    # 1. Serial number
    # ------------------------------------------------------------------

    async def read_serial(self) -> str | None:
        """Read the 14-byte battery serial number (register 0x10)."""
        raw = await self.conn.read_reg(ADDR_BMS, BAT_SN, 14)
        if raw is None:
            return None
        serial = raw.decode("ascii", errors="replace").rstrip("\x00")
        self.data["serial"] = serial
        return serial

    # ------------------------------------------------------------------
    # 2. Firmware version
    # ------------------------------------------------------------------

    async def read_firmware_version(self) -> str | None:
        """Read the BMS firmware version (register 0x17).

        Decodes the 16-bit value as ``Vmajor.minor.patch`` where the high
        nibble is major, the next nibble is minor, and the low byte is
        patch.  E.g. ``0x0134`` becomes ``V1.3.4``.
        """
        raw = await self.conn.read_reg(ADDR_BMS, BAT_FW_VER, 2)
        if raw is None:
            return None
        val = _u16(raw)
        major = (val >> 8) & 0x0F
        minor = (val >> 4) & 0x0F
        patch = val & 0x0F
        version = f"V{major}.{minor}.{patch}"
        self.data["fw_version"] = version
        return version

    # ------------------------------------------------------------------
    # 3. Capacity info
    # ------------------------------------------------------------------

    async def read_capacity_info(self) -> dict | None:
        """Read design/full/remaining capacity and percentage."""
        results: dict[str, int] = {}

        raw = await self.conn.read_reg(ADDR_BMS, BAT_DESIGN_CAP, 2)
        if raw is None:
            return None
        results["design_cap"] = _u16(raw)

        raw = await self.conn.read_reg(ADDR_BMS, BAT_FULL_CAP, 2)
        if raw is None:
            return None
        results["full_cap"] = _u16(raw)

        raw = await self.conn.read_reg(ADDR_BMS, BAT_REMAINING_CAP, 2)
        if raw is None:
            return None
        results["remaining_cap"] = _u16(raw)

        raw = await self.conn.read_reg(ADDR_BMS, BAT_REMAINING_PCT, 2)
        if raw is None:
            return None
        results["remaining_pct"] = _s16(raw)

        self.data.update(results)
        return results

    # ------------------------------------------------------------------
    # 4. Electrical readings
    # ------------------------------------------------------------------

    async def read_electrical(self) -> dict | None:
        """Read current, voltage, and temperature from the BMS.

        Returns a dict with:
        - ``current_a``: float, amps (positive = discharge, negative = charge)
        - ``voltage_v``: float, volts
        - ``temp1_c``: int, sensor 1 temperature in Celsius
        - ``temp2_c``: int, sensor 2 temperature in Celsius
        """
        raw_cur = await self.conn.read_reg(ADDR_BMS, BAT_CURRENT, 2)
        if raw_cur is None:
            return None
        raw_volt = await self.conn.read_reg(ADDR_BMS, BAT_VOLTAGE, 2)
        if raw_volt is None:
            return None
        raw_temp = await self.conn.read_reg(ADDR_BMS, BAT_TEMP, 2)
        if raw_temp is None:
            return None

        current_raw = _s16(raw_cur)
        current_a = current_raw / 100.0

        voltage_raw = _s16(raw_volt)
        voltage_v = voltage_raw / 100.0

        temp_raw = _u16(raw_temp)
        temp1_c = (temp_raw & 0xFF) - 20
        temp2_c = ((temp_raw >> 8) & 0xFF) - 20

        result = {
            "current_a": current_a,
            "voltage_v": voltage_v,
            "temp1_c": temp1_c,
            "temp2_c": temp2_c,
        }
        self.data.update(result)
        return result

    # ------------------------------------------------------------------
    # 5. Status flags
    # ------------------------------------------------------------------

    async def read_status_flags(self) -> dict | None:
        """Read register 0x30 and decode all 12 status flag bits."""
        raw = await self.conn.read_reg(ADDR_BMS, BAT_STATUS, 2)
        if raw is None:
            return None

        status = _u16(raw)
        flags: dict[str, bool] = {}
        warnings: list[str] = []

        for mask, key, label in _FLAG_DEFS:
            active = bool(status & mask)
            flags[key] = active
            if active and mask in _WARN_FLAGS:
                warnings.append(label)

        self.data["flags"] = flags
        self.data["flag_warnings"] = warnings
        self.data["status_raw"] = status
        return flags

    # ------------------------------------------------------------------
    # 6. Cell voltages
    # ------------------------------------------------------------------

    async def read_cell_voltages(self) -> list[float] | None:
        """Read all 10 cell voltages (registers 0x40-0x49).

        Returns a list of voltages in volts.
        """
        raw = await self.conn.read_reg(ADDR_BMS, BAT_CELL_BASE, NUM_CELLS * 2)
        if raw is None:
            return None

        cells: list[float] = []
        for i in range(NUM_CELLS):
            mv = _u16(raw, i * 2)
            cells.append(mv / 1000.0)

        self.data["cells"] = cells
        return cells

    # ------------------------------------------------------------------
    # 7. Protection state (bitmaps)
    # ------------------------------------------------------------------

    async def read_protection_state(self) -> dict | None:
        """Read balancing, undervoltage, and overvoltage bitmaps."""
        raw_bal = await self.conn.read_reg(ADDR_BMS, BAT_BALANCE, 2)
        if raw_bal is None:
            return None
        raw_uv = await self.conn.read_reg(ADDR_BMS, BAT_UNDERVOLT, 2)
        if raw_uv is None:
            return None
        raw_ov = await self.conn.read_reg(ADDR_BMS, BAT_OVERVOLT, 2)
        if raw_ov is None:
            return None

        result = {
            "balancing": _decode_bitmap(_u16(raw_bal)),
            "undervoltage": _decode_bitmap(_u16(raw_uv)),
            "overvoltage": _decode_bitmap(_u16(raw_ov)),
        }
        self.data["protection"] = result
        return result

    # ------------------------------------------------------------------
    # 8. Health info
    # ------------------------------------------------------------------

    async def read_health_info(self) -> dict | None:
        """Read cycle count, charge count, over-discharge info, health,
        coulomb counter, and voltage-based capacity."""
        raw = await self.conn.read_reg(ADDR_BMS, BAT_CYCLE_TIMES, 2)
        if raw is None:
            return None
        cycle_times = _u16(raw)

        raw = await self.conn.read_reg(ADDR_BMS, BAT_CHARGE_TIMES, 2)
        if raw is None:
            return None
        charge_times = _u16(raw)

        raw = await self.conn.read_reg(ADDR_BMS, BAT_OVER_DIS_TIMES, 2)
        if raw is None:
            return None
        od_raw = _u16(raw)
        overflow_count = od_raw & 0xFF
        over_discharge_count = (od_raw >> 8) & 0xFF

        raw = await self.conn.read_reg(ADDR_BMS, BAT_HEALTH, 2)
        if raw is None:
            return None
        health_pct = _s16(raw)

        raw = await self.conn.read_reg(ADDR_BMS, BAT_COULOMB_CAP, 2)
        if raw is None:
            return None
        coulomb_cap = _s16(raw)

        raw = await self.conn.read_reg(ADDR_BMS, BAT_VOLT_CAP, 2)
        if raw is None:
            return None
        volt_cap = _s16(raw)

        result = {
            "cycle_times": cycle_times,
            "charge_times": charge_times,
            "overflow_count": overflow_count,
            "over_discharge_count": over_discharge_count,
            "health_pct": health_pct,
            "coulomb_cap": coulomb_cap,
            "volt_cap": volt_cap,
        }
        self.data.update(result)
        return result

    # ------------------------------------------------------------------
    # 9. ESC error code
    # ------------------------------------------------------------------

    async def read_esc_error(self) -> int | None:
        """Read the ESC error register (from ADDR_ESC, not BMS).

        Returns the raw error code and stores the human-readable
        description in ``self.data["esc_error_desc"]``.
        """
        raw = await self.conn.read_reg(ADDR_ESC, ESC_ERROR, 2)
        if raw is None:
            return None
        code = _u16(raw)
        desc = _ESC_ERROR_MAP.get(code, f"Unknown error (code {code})" if code != 0 else "None")
        self.data["esc_error"] = code
        self.data["esc_error_desc"] = desc
        return code

    # ------------------------------------------------------------------
    # 10. Full diagnostic
    # ------------------------------------------------------------------

    async def full_diagnostic(self) -> dict:
        """Run every read method and return the complete data dict."""
        await self.read_serial()
        await self.read_firmware_version()
        await self.read_capacity_info()
        await self.read_electrical()
        await self.read_status_flags()
        await self.read_cell_voltages()
        await self.read_protection_state()
        await self.read_health_info()
        await self.read_esc_error()
        return self.data

    # ------------------------------------------------------------------
    # 11. Pretty-print diagnostic
    # ------------------------------------------------------------------

    def print_diagnostic(self) -> None:
        """Pretty-print all diagnostic data in a formatted report."""
        d = self.data
        W = 50  # report width

        def _hdr(title: str) -> str:
            return f"\n\u2500\u2500 {title} " + "\u2500" * max(0, W - len(title) - 4)

        # Title
        print()
        print("\u2550" * W)
        print("  NINEBOT F2 PRO \u2014 BMS DIAGNOSTIC REPORT")
        print("\u2550" * W)

        # Identity
        serial = d.get("serial", "N/A")
        fw = d.get("fw_version", "N/A")
        esc_err = d.get("esc_error", None)
        esc_desc = d.get("esc_error_desc", "N/A")
        esc_display = esc_desc if esc_err is not None else "N/A"
        if esc_err is not None and esc_err != 0:
            esc_display = f"{esc_err} - {esc_desc}"

        print(f"\n  Serial:         {serial}")
        print(f"  BMS Firmware:   {fw}")
        print(f"  ESC Error Code: {esc_display}")

        # Battery status
        print(_hdr("BATTERY STATUS"))

        voltage = d.get("voltage_v")
        current = d.get("current_a")
        temp1 = d.get("temp1_c")
        temp2 = d.get("temp2_c")
        rem_cap = d.get("remaining_cap")
        full_cap = d.get("full_cap")
        design_cap = d.get("design_cap")
        rem_pct = d.get("remaining_pct")
        health = d.get("health_pct")
        cycles = d.get("cycle_times")

        if voltage is not None:
            print(f"  Pack Voltage:   {voltage:.2f}V")
        if current is not None:
            if abs(current) < 0.01:
                state = "(idle)"
            elif current > 0:
                state = "(discharging)"
            else:
                state = "(charging)"
            print(f"  Current:        {current:.2f}A {state}")
        if temp1 is not None and temp2 is not None:
            print(f"  Temperature:    Sensor 1: {temp1}\u00b0C  Sensor 2: {temp2}\u00b0C")
        if rem_cap is not None and full_cap is not None and rem_pct is not None:
            print(f"  Remaining:      {rem_cap} / {full_cap} mAh ({rem_pct}%)")
        if full_cap is not None and design_cap is not None:
            print(f"  Full Charge Cap: {full_cap} mAh (design: {design_cap} mAh)")
        if health is not None:
            print(f"  Health:         {health}%")
        if cycles is not None:
            print(f"  Charge Cycles:  {cycles}")

        # Status flags
        flags = d.get("flags")
        if flags is not None:
            print(_hdr("STATUS FLAGS"))
            for _mask, key, label in _FLAG_DEFS:
                active = flags.get(key, False)
                if _mask in _WARN_FLAGS:
                    if active:
                        icon = "\u26a0\ufe0f "
                        print(f"  {icon} {label}")
                    else:
                        print(f"  \u2705 {label}: Clear")
                else:
                    if active:
                        print(f"  \u2705 {label}")
                    else:
                        print(f"  \u274c {label}")

        # Cell voltages
        cells = d.get("cells")
        if cells is not None:
            print(_hdr("CELL VOLTAGES"))
            avg_v = sum(cells) / len(cells) if cells else 0.0
            max_v = max(cells) if cells else 0.0
            min_v = min(cells) if cells else 0.0
            max_idx = cells.index(max_v) + 1
            min_idx = cells.index(min_v) + 1
            delta = max_v - min_v

            # Bar chart parameters: scale 2.5V-4.2V across 20 chars
            bar_min = 2.5
            bar_max = 4.2
            bar_width = 20

            for i, v in enumerate(cells, start=1):
                # Bar fill
                frac = max(0.0, min(1.0, (v - bar_min) / (bar_max - bar_min)))
                filled = round(frac * bar_width)
                bar = "\u2588" * filled + "\u2591" * (bar_width - filled)

                # Deviation from average
                dev = v - avg_v
                if i == max_idx and delta < 0.001:
                    suffix = "  (ref)"
                else:
                    suffix = f"  {dev:+.3f}V"

                # Warn if >100mV from average or below 2.5V
                warn = ""
                if abs(dev) > 0.100:
                    warn = " \u26a0\ufe0f  IMBALANCE"
                if v < 2.5:
                    warn = " \u26a0\ufe0f  DEAD CELL"
                elif v < 3.0:
                    warn = " \u26a0\ufe0f  LOW"

                print(f"  Cell {i:2d}:  {v:.3f}V  {bar} {suffix}{warn}")

            print()
            print(f"  Max:     {max_v:.3f}V  (Cell {max_idx})")
            print(f"  Min:     {min_v:.3f}V  (Cell {min_idx})")
            delta_warn = "  \u26a0\ufe0f  IMBALANCE DETECTED" if delta > 0.100 else ""
            print(f"  Delta:   {delta:.3f}V{delta_warn}")
            print(f"  Average: {avg_v:.3f}V")

        # Protection state
        prot = d.get("protection")
        if prot is not None:
            print(_hdr("PROTECTION STATE"))
            bal = prot.get("balancing", [])
            uv = prot.get("undervoltage", [])
            ov = prot.get("overvoltage", [])
            bal_str = ", ".join(f"Cell {c}" for c in bal) if bal else "None"
            uv_str = (", ".join(f"Cell {c}" for c in uv) + " \u26a0\ufe0f") if uv else "None"
            ov_str = (", ".join(f"Cell {c}" for c in ov) + " \u26a0\ufe0f") if ov else "None"
            print(f"  Balancing:    {bal_str}")
            print(f"  Undervoltage: {uv_str}")
            print(f"  Overvoltage:  {ov_str}")

        # SOC calibration
        coulomb = d.get("coulomb_cap")
        volt_cap = d.get("volt_cap")
        if coulomb is not None or volt_cap is not None:
            print(_hdr("SOC CALIBRATION"))
            if coulomb is not None:
                print(f"  Coulomb Counter: {coulomb} mAh")
            if volt_cap is not None:
                print(f"  Voltage Estimate: {volt_cap} mAh")
            if rem_cap is not None and rem_pct is not None:
                print(f"  Reported:         {rem_cap} mAh ({rem_pct}%)")
            if coulomb is not None and volt_cap is not None:
                diff = abs(coulomb - volt_cap)
                if diff > 50:
                    print(f"  Discrepancy:      \u26a0\ufe0f  Coulomb vs Voltage differ by {diff} mAh")
                else:
                    print(f"  Discrepancy:      OK (delta {diff} mAh)")

        # Diagnosis summary
        print()
        print("\u2550" * W)
        print("  DIAGNOSIS SUMMARY")
        print("\u2550" * W)

        issues: list[str] = []

        if flags and flags.get("chg_protect"):
            issues.append("Charge protection is blocking charging")
        if full_cap is not None and design_cap is not None and full_cap != design_cap:
            issues.append(
                f"Full charge capacity mismatch ({full_cap} vs design {design_cap} mAh) "
                "- SOC miscalibration likely"
            )
        if coulomb is not None and volt_cap is not None and abs(coulomb - volt_cap) > 50:
            issues.append(
                f"SOC estimators disagree (coulomb {coulomb} vs voltage {volt_cap} mAh) "
                "- recalibration needed"
            )
        if prot:
            uv_cells = prot.get("undervoltage", [])
            if uv_cells:
                cell_list = ", ".join(str(c) for c in uv_cells)
                issues.append(f"Cell(s) flagged for undervoltage: {cell_list}")
        if cells:
            dead = [i + 1 for i, v in enumerate(cells) if v < 2.5]
            if dead:
                cell_list = ", ".join(str(c) for c in dead)
                issues.append(f"DEAD CELL DETECTED (Cell {cell_list}) - may be unrecoverable")
        if flags and flags.get("dis_over"):
            issues.append("Over-discharge protection is active")
        if flags and flags.get("chg_over"):
            issues.append("Over-charge protection is active")
        if flags and flags.get("over_temp"):
            issues.append("Over-temperature protection is active")
        if esc_err is not None and esc_err != 0:
            issues.append(f"ESC reports error {esc_err}: {esc_desc}")

        if issues:
            for issue in issues:
                print(f"  \u26a0\ufe0f  {issue}")
        else:
            print("  \u2705 No faults detected. BMS appears healthy.")

        print()
        print("\u2550" * W)
