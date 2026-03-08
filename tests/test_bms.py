"""
Unit tests for the BMS register constants and BMSDiagnostic parsing logic.

All tests run WITHOUT hardware -- no BLE connection needed.
"""

from ninebot_bms.bms import (
    BAT_SN,
    BAT_FW_VER,
    BAT_DESIGN_CAP,
    BAT_FULL_CAP,
    BAT_STATUS,
    BAT_REMAINING_CAP,
    BAT_REMAINING_PCT,
    BAT_CURRENT,
    BAT_VOLTAGE,
    BAT_TEMP,
    BAT_CELL_BASE,
    NUM_CELLS,
    BMS_FLAG_CHG_PROTECT,
    BMS_FLAG_WRITE_LOCK,
    BMS_FLAG_ACTIVATED,
    BMSDiagnostic,
)


# ============================================================================
# Register Address Tests
# ============================================================================


def test_register_addresses():
    """Verify register addresses match the official Ninebot protocol doc."""
    assert BAT_SN == 0x10
    assert BAT_FW_VER == 0x17
    assert BAT_DESIGN_CAP == 0x18
    assert BAT_FULL_CAP == 0x19
    assert BAT_STATUS == 0x30
    assert BAT_REMAINING_CAP == 0x31
    assert BAT_REMAINING_PCT == 0x32
    assert BAT_CURRENT == 0x33
    assert BAT_VOLTAGE == 0x34
    assert BAT_TEMP == 0x35
    assert BAT_CELL_BASE == 0x40
    assert NUM_CELLS == 10


# ============================================================================
# Flag Bit Mask Tests
# ============================================================================


def test_flag_bits():
    """Verify flag bit masks are correct."""
    assert BMS_FLAG_CHG_PROTECT == 0x0004
    assert BMS_FLAG_WRITE_LOCK == 0x0010
    assert BMS_FLAG_ACTIVATED == 0x0002


# ============================================================================
# Cell Voltage Register Range Tests
# ============================================================================


def test_cell_voltage_register_range():
    """Cell voltage registers should be 0x40 through 0x49 for 10S pack."""
    for i in range(NUM_CELLS):
        reg = BAT_CELL_BASE + i
        assert 0x40 <= reg <= 0x49


def test_cell_voltage_register_count():
    """There should be exactly 10 cell voltage registers."""
    registers = [BAT_CELL_BASE + i for i in range(NUM_CELLS)]
    assert len(registers) == 10
    # No duplicates
    assert len(set(registers)) == 10


# ============================================================================
# BMSDiagnostic Instantiation Tests
# ============================================================================


def test_bms_diagnostic_init():
    """BMSDiagnostic should initialize with empty data dict."""

    class FakeConn:
        pass

    diag = BMSDiagnostic(FakeConn())
    assert diag.data == {}
    assert diag.conn is not None
