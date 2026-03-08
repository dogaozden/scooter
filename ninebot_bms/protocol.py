"""
Ninebot F2 Pro BMS serial protocol engine.

Implements the Ninebot ESC/BMS binary protocol for building, parsing,
and validating command packets. This module is pure Python with zero
external dependencies.

Packet structure
----------------
::

    5A A5  bLen  bSrcAddr  bDstAddr  bCmd  bDataIndex  bDataSegment[N]  chkLo  chkHi
    -----  ----  --------  --------  ----  ----------  ---------------  -----------
    header  len    src       dst      cmd     reg         data[0..N-1]   checksum

- **Header** (2 bytes): always ``0x5A 0xA5``
- **bLen** (1 byte): length of ``bDataSegment`` only
- **bSrcAddr / bDstAddr** (1 byte each): source and destination addresses
- **bCmd** (1 byte): command code
- **bDataIndex** (1 byte): register / data index
- **bDataSegment** (N bytes): payload (may be empty)
- **Checksum** (2 bytes, little-endian): ``~sum(bLen..bDataSegment[-1]) & 0xFFFF``

Total packet length = 2 (header) + 1 (len) + 1 (src) + 1 (dst)
                    + 1 (cmd) + 1 (reg) + len (data) + 2 (checksum)
                    = 9 + len
"""

from __future__ import annotations

import struct

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Packet header
HEADER = b"\x5A\xA5"

# Device addresses
ADDR_ESC: int = 0x20
ADDR_BLE: int = 0x21
ADDR_BMS: int = 0x22
ADDR_EXT_BMS: int = 0x23
ADDR_PC: int = 0x3D
ADDR_APP: int = 0x3E

# Commands
CMD_READ: int = 0x01
CMD_WRITE: int = 0x02
CMD_WRITE_NO_REPLY: int = 0x03
CMD_READ_RESP: int = 0x04
CMD_WRITE_RESP: int = 0x05
CMD_CLEAR_ERROR: int = 0x06
CMD_IAP_BEGIN: int = 0x07
CMD_IAP_TRANS: int = 0x08
CMD_IAP_VERIFY: int = 0x09
CMD_MCU_RESET: int = 0x0A
CMD_INIT: int = 0x5B
CMD_PING: int = 0x5C
CMD_PAIR: int = 0x5D

# Write response codes
WRITE_SUCCESS: int = 0x00
WRITE_ERR_AUTH: int = 0x01
WRITE_ERR_BUSY: int = 0x02
WRITE_ERR_SIZE: int = 0x03
WRITE_ERR_FORMAT: int = 0x04

_WRITE_ERROR_MESSAGES: dict[int, str] = {
    WRITE_SUCCESS: "Success",
    WRITE_ERR_AUTH: "Authentication error",
    WRITE_ERR_BUSY: "Device busy",
    WRITE_ERR_SIZE: "Invalid data size",
    WRITE_ERR_FORMAT: "Invalid data format",
}


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------


def calc_checksum(data: bytes) -> bytes:
    """Compute the Ninebot protocol checksum.

    Parameters
    ----------
    data:
        All bytes *after* the 2-byte header (``5A A5``), i.e.
        ``bLen + bSrcAddr + bDstAddr + bCmd + bDataIndex + bDataSegment[N]``.

    Returns
    -------
    bytes
        2-byte checksum in **little-endian** order, computed as
        ``~sum(data) & 0xFFFF``.
    """
    s = sum(data) & 0xFFFF
    chk = (~s) & 0xFFFF
    return struct.pack("<H", chk)


def build_packet(src: int, dst: int, cmd: int, reg: int, data: bytes = b"") -> bytes:
    """Build a complete Ninebot protocol packet.

    Parameters
    ----------
    src:
        Source device address (e.g. ``ADDR_APP``).
    dst:
        Destination device address (e.g. ``ADDR_BMS``).
    cmd:
        Command byte (e.g. ``CMD_READ``).
    reg:
        Register / data-index byte.
    data:
        Optional payload bytes.

    Returns
    -------
    bytes
        The fully-formed packet:
        ``5A A5 <len> <src> <dst> <cmd> <reg> <data...> <chk_lo> <chk_hi>``

    Notes
    -----
    ``len`` encodes the length of *data* only (not src/dst/cmd/reg).
    The checksum covers ``len + src + dst + cmd + reg + data``.
    """
    length = len(data)
    body = bytes([length, src, dst, cmd, reg]) + data
    checksum = calc_checksum(body)
    return HEADER + body + checksum


def parse_packet(raw: bytes) -> dict[str, object] | None:
    """Parse a raw byte sequence into a protocol packet dict.

    Parameters
    ----------
    raw:
        Raw bytes that should start with the ``5A A5`` header.

    Returns
    -------
    dict | None
        A dict with keys ``src``, ``dst``, ``cmd``, ``reg``, ``data``,
        and ``valid`` (bool indicating whether the checksum matched).
        Returns ``None`` if the packet is too short or has an invalid
        header.
    """
    # Minimum viable packet: header(2) + len(1) + src(1) + dst(1)
    #                        + cmd(1) + reg(1) + checksum(2) = 9
    if len(raw) < 9:
        return None

    if raw[0:2] != HEADER:
        return None

    data_len = raw[2]
    expected_total = 9 + data_len
    if len(raw) < expected_total:
        return None

    src = raw[3]
    dst = raw[4]
    cmd = raw[5]
    reg = raw[6]
    data = raw[7 : 7 + data_len]

    # Checksum validation: covers bytes from raw[2] through end of data
    body = raw[2 : 7 + data_len]
    expected_chk = calc_checksum(body)
    actual_chk = raw[7 + data_len : 9 + data_len]
    valid = expected_chk == actual_chk

    return {
        "src": src,
        "dst": dst,
        "cmd": cmd,
        "reg": reg,
        "data": bytes(data),
        "valid": valid,
    }


def is_packet_complete(buf: bytearray) -> bool:
    """Check whether *buf* contains at least one complete packet.

    Parameters
    ----------
    buf:
        A bytearray of accumulated serial/BLE bytes.

    Returns
    -------
    bool
        ``True`` if a full packet (header through checksum) is present.
    """
    # Scan forward for the header
    idx = _find_header(buf)
    if idx is None:
        return False

    remaining = len(buf) - idx
    # Need at least header(2) + len(1) = 3 bytes to read data_len
    if remaining < 3:
        return False

    data_len = buf[idx + 2]
    total = 9 + data_len
    return remaining >= total


def extract_packet(buf: bytearray) -> tuple[bytes | None, bytearray]:
    """Extract the first complete packet from a byte buffer.

    Leading garbage bytes (anything before the first ``5A A5`` header)
    are silently discarded.

    Parameters
    ----------
    buf:
        A mutable bytearray of accumulated bytes.

    Returns
    -------
    tuple[bytes | None, bytearray]
        ``(packet_bytes, remaining_buffer)`` if a complete packet was
        found, otherwise ``(None, original_buffer)``.
    """
    idx = _find_header(buf)
    if idx is None:
        return None, buf

    remaining = len(buf) - idx
    if remaining < 3:
        # Can't even read the length byte yet — keep the header for next time
        return None, bytearray(buf[idx:])

    data_len = buf[idx + 2]
    total = 9 + data_len

    if remaining < total:
        # Incomplete packet — trim leading garbage but keep partial packet
        return None, bytearray(buf[idx:])

    packet = bytes(buf[idx : idx + total])
    leftover = bytearray(buf[idx + total :])
    return packet, leftover


# ---------------------------------------------------------------------------
# Convenience builders
# ---------------------------------------------------------------------------


def build_read_cmd(dst: int, reg: int, length: int) -> bytes:
    """Build a register-read command packet.

    Parameters
    ----------
    dst:
        Target device address (e.g. ``ADDR_BMS``).
    reg:
        Starting register address.
    length:
        Number of bytes to read from the target.

    Returns
    -------
    bytes
        A complete ``CMD_READ`` packet with ``src=ADDR_PC``.
    """
    return build_packet(ADDR_PC, dst, CMD_READ, reg, bytes([length]))


def build_write_cmd(
    dst: int, reg: int, value: int, with_reply: bool = True
) -> bytes:
    """Build a single-register write command (U16 little-endian).

    Parameters
    ----------
    dst:
        Target device address.
    reg:
        Register address to write.
    value:
        16-bit unsigned value to write.
    with_reply:
        If ``True`` use ``CMD_WRITE`` (expects acknowledgement).
        If ``False`` use ``CMD_WRITE_NO_REPLY``.

    Returns
    -------
    bytes
        A complete write packet with ``src=ADDR_PC``.
    """
    cmd = CMD_WRITE if with_reply else CMD_WRITE_NO_REPLY
    data = struct.pack("<H", value)
    return build_packet(ADDR_PC, dst, cmd, reg, data)


def build_write_bytes_cmd(
    dst: int, reg: int, data: bytes, with_reply: bool = True
) -> bytes:
    """Build a multi-register write command with arbitrary payload.

    Parameters
    ----------
    dst:
        Target device address.
    reg:
        Starting register address.
    data:
        Raw bytes to write.
    with_reply:
        If ``True`` use ``CMD_WRITE``; otherwise ``CMD_WRITE_NO_REPLY``.

    Returns
    -------
    bytes
        A complete write packet with ``src=ADDR_PC``.
    """
    cmd = CMD_WRITE if with_reply else CMD_WRITE_NO_REPLY
    return build_packet(ADDR_PC, dst, cmd, reg, data)


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------


def parse_write_response(packet: dict[str, object]) -> tuple[bool, str]:
    """Interpret a write-response packet (``CMD_WRITE_RESP = 0x05``).

    Parameters
    ----------
    packet:
        A dict as returned by :func:`parse_packet`.

    Returns
    -------
    tuple[bool, str]
        ``(success, message)`` where *success* is ``True`` when the
        device acknowledged a successful write, and *message* is a
        human-readable description of the result.
    """
    data: bytes = packet.get("data", b"")  # type: ignore[assignment]
    if not data:
        return False, "Empty write response (no status byte)"

    code = data[0]
    message = _WRITE_ERROR_MESSAGES.get(code, f"Unknown error code 0x{code:02X}")
    success = code == WRITE_SUCCESS
    return success, message


# ---------------------------------------------------------------------------
# Debug / display
# ---------------------------------------------------------------------------


def format_packet_hex(packet: bytes) -> str:
    """Format a raw packet as a human-readable hex string.

    Parameters
    ----------
    packet:
        Raw packet bytes.

    Returns
    -------
    str
        Space-separated uppercase hex, e.g.
        ``"5A A5 01 3E 22 01 40 14 XX XX"``.
    """
    return " ".join(f"{b:02X}" for b in packet)


# ---------------------------------------------------------------------------
# Internal utilities
# ---------------------------------------------------------------------------


def _find_header(buf: bytearray | bytes) -> int | None:
    """Locate the first occurrence of the ``5A A5`` header in *buf*.

    Returns
    -------
    int | None
        Index of the first header byte, or ``None`` if not found.
    """
    idx = 0
    while idx <= len(buf) - 2:
        if buf[idx] == 0x5A and buf[idx + 1] == 0xA5:
            return idx
        idx += 1
    return None
