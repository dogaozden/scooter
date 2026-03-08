"""
Thorough unit tests for the Ninebot F2 Pro BMS protocol layer.

All tests run WITHOUT hardware -- no BLE connection needed.
"""

from ninebot_bms.protocol import (
    HEADER,
    ADDR_ESC,
    ADDR_BLE,
    ADDR_BMS,
    ADDR_EXT_BMS,
    ADDR_PC,
    ADDR_APP,
    CMD_READ,
    CMD_WRITE,
    CMD_WRITE_NO_REPLY,
    CMD_READ_RESP,
    CMD_WRITE_RESP,
    CMD_CLEAR_ERROR,
    CMD_IAP_BEGIN,
    CMD_IAP_TRANS,
    CMD_IAP_VERIFY,
    CMD_MCU_RESET,
    CMD_INIT,
    CMD_PING,
    CMD_PAIR,
    WRITE_SUCCESS,
    WRITE_ERR_AUTH,
    WRITE_ERR_BUSY,
    WRITE_ERR_SIZE,
    WRITE_ERR_FORMAT,
    calc_checksum,
    build_packet,
    parse_packet,
    is_packet_complete,
    extract_packet,
    build_read_cmd,
    build_write_cmd,
    build_write_bytes_cmd,
    parse_write_response,
    format_packet_hex,
)


# ============================================================================
# 1. Checksum Tests
# ============================================================================


def test_checksum_simple():
    """Known example: reading ESC body temp register 0x3E.

    Packet (without header): 01 3D 20 01 3E 02
    bLen=01, src=3D, dst=20, cmd=01, reg=3E, data=02
    sum = 0x01 + 0x3D + 0x20 + 0x01 + 0x3E + 0x02 = 0x9F
    ~0x9F & 0xFFFF = 0xFF60
    little-endian: 0x60, 0xFF
    """
    data = bytes([0x01, 0x3D, 0x20, 0x01, 0x3E, 0x02])
    checksum = calc_checksum(data)
    assert checksum == bytes([0x60, 0xFF])


def test_checksum_zero_data():
    """Edge case: minimal packet body (MCU reset, no payload data)."""
    data = bytes([0x00, 0x3E, 0x22, 0x0A, 0x00])
    checksum = calc_checksum(data)
    expected = (~(0x00 + 0x3E + 0x22 + 0x0A + 0x00)) & 0xFFFF
    assert int.from_bytes(checksum, "little") == expected


def test_checksum_with_payload():
    """Write value 0x0001 to ESC register 0x78 (reboot).

    bLen=02, src=3E, dst=20, cmd=02, reg=78, data=01 00
    """
    data = bytes([0x02, 0x3E, 0x20, 0x02, 0x78, 0x01, 0x00])
    checksum = calc_checksum(data)
    total = sum(data) & 0xFFFF
    expected = (~total) & 0xFFFF
    assert int.from_bytes(checksum, "little") == expected


def test_checksum_returns_two_bytes():
    """Checksum must always be exactly 2 bytes."""
    data = bytes([0x00])
    checksum = calc_checksum(data)
    assert len(checksum) == 2


def test_checksum_deterministic():
    """Same input must always produce same output."""
    data = bytes([0x01, 0x3D, 0x20, 0x01, 0x3E, 0x02])
    c1 = calc_checksum(data)
    c2 = calc_checksum(data)
    assert c1 == c2


def test_checksum_overflow():
    """Large payload that overflows 16-bit sum multiple times."""
    data = bytes([0xFF] * 300)
    checksum = calc_checksum(data)
    assert len(checksum) == 2
    # Verify manually
    total = (0xFF * 300) & 0xFFFF
    expected = (~total) & 0xFFFF
    assert int.from_bytes(checksum, "little") == expected


def test_checksum_empty_data():
    """Empty data should produce checksum of ~0 & 0xFFFF = 0xFFFF."""
    checksum = calc_checksum(b"")
    assert int.from_bytes(checksum, "little") == 0xFFFF


# ============================================================================
# 2. Packet Building Tests
# ============================================================================


def test_build_packet_read_cell_voltages():
    """Read 20 bytes from BMS register 0x40."""
    pkt = build_packet(ADDR_APP, ADDR_BMS, CMD_READ, 0x40, bytes([20]))
    assert pkt[:2] == HEADER
    assert pkt[2] == 1          # len = 1 byte of data
    assert pkt[3] == ADDR_APP   # src
    assert pkt[4] == ADDR_BMS   # dst
    assert pkt[5] == CMD_READ   # cmd
    assert pkt[6] == 0x40       # reg
    assert pkt[7] == 20         # data: read 20 bytes
    assert len(pkt) == 10       # 2+1+1+1+1+1+1+2 = 10


def test_build_packet_mcu_reset():
    """MCU reset: no data."""
    pkt = build_packet(ADDR_APP, ADDR_BMS, CMD_MCU_RESET, 0x00)
    assert pkt[:2] == HEADER
    assert pkt[2] == 0          # no data
    assert len(pkt) == 9        # minimum packet size


def test_build_packet_write_u16():
    """Write 0x0001 to ESC register 0x78."""
    pkt = build_packet(ADDR_APP, ADDR_ESC, CMD_WRITE, 0x78, b"\x01\x00")
    assert pkt[2] == 2          # 2 bytes of data
    assert pkt[7:9] == b"\x01\x00"  # data
    assert len(pkt) == 11       # 9 + 2


def test_build_packet_checksum_valid():
    """Build any packet and verify parse_packet says it is valid."""
    pkt = build_packet(ADDR_APP, ADDR_BMS, CMD_READ, 0x40, bytes([20]))
    parsed = parse_packet(pkt)
    assert parsed is not None
    assert parsed["valid"] is True


def test_build_packet_header_always_present():
    """All built packets must start with 5A A5."""
    for cmd in [CMD_READ, CMD_WRITE, CMD_MCU_RESET, CMD_PING, CMD_INIT]:
        pkt = build_packet(ADDR_APP, ADDR_BMS, cmd, 0x00)
        assert pkt[:2] == HEADER, f"Header missing for cmd 0x{cmd:02X}"


def test_build_packet_length_field_matches_data():
    """The length byte must equal the data payload length."""
    for data_size in [0, 1, 5, 20, 128]:
        data = bytes(data_size)
        pkt = build_packet(ADDR_APP, ADDR_BMS, CMD_READ, 0x00, data)
        assert pkt[2] == data_size


def test_build_packet_total_length():
    """Total packet length should be 9 + len(data)."""
    for data_size in [0, 1, 10, 50, 200]:
        data = bytes(data_size)
        pkt = build_packet(ADDR_APP, ADDR_BMS, CMD_READ, 0x00, data)
        assert len(pkt) == 9 + data_size


# ============================================================================
# 3. Packet Parsing Tests
# ============================================================================


def test_parse_packet_roundtrip():
    """Build a packet and parse it back -- all fields must match."""
    pkt = build_packet(ADDR_APP, ADDR_BMS, CMD_READ, 0x40, bytes([20]))
    parsed = parse_packet(pkt)
    assert parsed["src"] == ADDR_APP
    assert parsed["dst"] == ADDR_BMS
    assert parsed["cmd"] == CMD_READ
    assert parsed["reg"] == 0x40
    assert parsed["data"] == bytes([20])
    assert parsed["valid"] is True


def test_parse_packet_bad_header():
    """Packet with wrong header should return None."""
    assert parse_packet(b"\xAA\xBB\x01\x3E\x22\x01\x40\x14\x00\x00") is None


def test_parse_packet_bad_checksum():
    """Corrupted checksum should parse but valid=False."""
    pkt = build_packet(ADDR_APP, ADDR_BMS, CMD_READ, 0x40, bytes([20]))
    corrupted = bytearray(pkt)
    corrupted[-1] ^= 0xFF  # flip checksum bits
    parsed = parse_packet(bytes(corrupted))
    assert parsed is not None   # should still parse
    assert parsed["valid"] is False  # but checksum should fail


def test_parse_packet_too_short():
    """Packet shorter than minimum 9 bytes should return None."""
    assert parse_packet(b"\x5A\xA5\x01") is None


def test_parse_packet_empty():
    """Empty bytes should return None."""
    assert parse_packet(b"") is None


def test_parse_simulated_read_response():
    """Simulate a BMS response with 20 bytes of cell voltage data (10 cells)."""
    cell_data = b""
    for mv in [3560, 3540, 3210, 3570, 3580, 3420, 3210, 3550, 3500, 3480]:
        cell_data += mv.to_bytes(2, "little")
    pkt = build_packet(ADDR_BMS, ADDR_APP, CMD_READ_RESP, 0x40, cell_data)
    parsed = parse_packet(pkt)
    assert parsed["valid"] is True
    assert parsed["cmd"] == CMD_READ_RESP
    assert len(parsed["data"]) == 20
    # Verify first cell voltage
    v1 = int.from_bytes(parsed["data"][0:2], "little")
    assert v1 == 3560


def test_parse_write_response_success():
    """Write response with status=WRITE_SUCCESS in reg field."""
    pkt = build_packet(ADDR_BMS, ADDR_APP, CMD_WRITE_RESP, WRITE_SUCCESS)
    parsed = parse_packet(pkt)
    assert parsed["cmd"] == CMD_WRITE_RESP
    assert parsed["reg"] == WRITE_SUCCESS


def test_parse_write_response_auth_error():
    """Write response for auth error via parse_write_response helper.

    parse_write_response reads the status from data[0], so we put the
    error code in the data payload.
    """
    pkt = build_packet(
        ADDR_BMS, ADDR_APP, CMD_WRITE_RESP, 0x00,
        bytes([WRITE_ERR_AUTH]),
    )
    parsed = parse_packet(pkt)
    success, msg = parse_write_response(parsed)
    assert success is False
    assert "auth" in msg.lower()


def test_parse_packet_no_data():
    """Parse a packet that has no data payload."""
    pkt = build_packet(ADDR_APP, ADDR_ESC, CMD_MCU_RESET, 0x00)
    parsed = parse_packet(pkt)
    assert parsed is not None
    assert parsed["data"] == b""
    assert parsed["valid"] is True


def test_parse_packet_preserves_all_addresses():
    """Ensure all address constants roundtrip correctly."""
    for src, dst in [
        (ADDR_APP, ADDR_BMS),
        (ADDR_APP, ADDR_ESC),
        (ADDR_BMS, ADDR_APP),
        (ADDR_PC, ADDR_BLE),
        (ADDR_APP, ADDR_EXT_BMS),
    ]:
        pkt = build_packet(src, dst, CMD_READ, 0x00)
        parsed = parse_packet(pkt)
        assert parsed["src"] == src
        assert parsed["dst"] == dst


def test_parse_packet_preserves_all_commands():
    """Ensure all command constants roundtrip correctly."""
    for cmd in [
        CMD_READ, CMD_WRITE, CMD_WRITE_NO_REPLY, CMD_READ_RESP,
        CMD_WRITE_RESP, CMD_CLEAR_ERROR, CMD_IAP_BEGIN, CMD_IAP_TRANS,
        CMD_IAP_VERIFY, CMD_MCU_RESET, CMD_INIT, CMD_PING, CMD_PAIR,
    ]:
        pkt = build_packet(ADDR_APP, ADDR_BMS, cmd, 0x00)
        parsed = parse_packet(pkt)
        assert parsed["cmd"] == cmd


def test_parse_packet_length_mismatch():
    """If raw is shorter than header+len declares, should return None."""
    # Build valid packet, then truncate it
    pkt = build_packet(ADDR_APP, ADDR_BMS, CMD_READ, 0x40, bytes([20]))
    truncated = pkt[:8]  # missing checksum and some data
    result = parse_packet(truncated)
    assert result is None


# ============================================================================
# 4. Buffer / Fragmentation Tests
# ============================================================================


def test_is_packet_complete_full_packet():
    """Complete packet in buffer should return True."""
    pkt = build_packet(ADDR_APP, ADDR_BMS, CMD_READ, 0x40, bytes([20]))
    buf = bytearray(pkt)
    assert is_packet_complete(buf) is True


def test_is_packet_complete_partial():
    """Partial packet (first 5 bytes only) should return False."""
    pkt = build_packet(ADDR_APP, ADDR_BMS, CMD_READ, 0x40, bytes([20]))
    buf = bytearray(pkt[:5])
    assert is_packet_complete(buf) is False


def test_is_packet_complete_empty():
    """Empty buffer should return False."""
    assert is_packet_complete(bytearray()) is False


def test_is_packet_complete_header_only():
    """Just the header bytes should return False."""
    assert is_packet_complete(bytearray(b"\x5A\xA5")) is False


def test_is_packet_complete_with_garbage_prefix():
    """Buffer with garbage before a complete packet."""
    pkt = build_packet(ADDR_APP, ADDR_BMS, CMD_READ, 0x40, bytes([20]))
    buf = bytearray(b"\xFF\xFE\xFD") + bytearray(pkt)
    assert is_packet_complete(buf) is True


def test_extract_packet_single():
    """Extract a single packet from a buffer with nothing else."""
    pkt = build_packet(ADDR_APP, ADDR_BMS, CMD_READ, 0x40, bytes([20]))
    extracted, remaining = extract_packet(bytearray(pkt))
    assert extracted == pkt
    assert len(remaining) == 0


def test_extract_packet_with_garbage_prefix():
    """Leading garbage before the packet should be silently discarded."""
    pkt = build_packet(ADDR_APP, ADDR_BMS, CMD_READ, 0x40, bytes([20]))
    buf = bytearray(b"\xFF\xFE\xFD") + bytearray(pkt)
    extracted, remaining = extract_packet(buf)
    assert extracted == pkt
    assert len(remaining) == 0


def test_extract_packet_two_packets():
    """Extract two consecutive packets one at a time."""
    pkt1 = build_packet(ADDR_APP, ADDR_BMS, CMD_READ, 0x40, bytes([20]))
    pkt2 = build_packet(ADDR_APP, ADDR_ESC, CMD_READ, 0x1B, bytes([2]))
    buf = bytearray(pkt1) + bytearray(pkt2)
    extracted1, remaining = extract_packet(buf)
    assert extracted1 == pkt1
    extracted2, remaining = extract_packet(remaining)
    assert extracted2 == pkt2
    assert len(remaining) == 0


def test_extract_packet_incomplete():
    """Incomplete packet should return None and preserve the buffer."""
    pkt = build_packet(ADDR_APP, ADDR_BMS, CMD_READ, 0x40, bytes([20]))
    buf = bytearray(pkt[:5])
    extracted, remaining = extract_packet(buf)
    assert extracted is None
    assert remaining == buf


def test_extract_packet_empty_buffer():
    """Empty buffer should return None."""
    extracted, remaining = extract_packet(bytearray())
    assert extracted is None
    assert remaining == bytearray()


def test_extract_packet_three_packets_sequential():
    """Extract three packets one after another."""
    pkts = [
        build_packet(ADDR_APP, ADDR_BMS, CMD_READ, 0x40, bytes([20])),
        build_packet(ADDR_APP, ADDR_ESC, CMD_WRITE, 0x78, b"\x01\x00"),
        build_packet(ADDR_BMS, ADDR_APP, CMD_READ_RESP, 0x40, bytes(10)),
    ]
    buf = bytearray()
    for p in pkts:
        buf += bytearray(p)

    for expected_pkt in pkts:
        extracted, buf = extract_packet(buf)
        assert extracted == expected_pkt
    assert len(buf) == 0


def test_extract_packet_garbage_between_packets():
    """Garbage between two packets: first extract gets pkt1, second gets pkt2."""
    pkt1 = build_packet(ADDR_APP, ADDR_BMS, CMD_READ, 0x40, bytes([20]))
    pkt2 = build_packet(ADDR_APP, ADDR_ESC, CMD_READ, 0x1B, bytes([2]))
    buf = bytearray(pkt1) + bytearray(b"\xFF\xFF\xFF") + bytearray(pkt2)
    extracted1, remaining = extract_packet(buf)
    assert extracted1 == pkt1
    extracted2, remaining = extract_packet(remaining)
    assert extracted2 == pkt2
    assert len(remaining) == 0


# ============================================================================
# 5. Convenience Function Tests
# ============================================================================


def test_build_read_cmd():
    """build_read_cmd should produce a valid CMD_READ packet from ADDR_PC."""
    pkt = build_read_cmd(ADDR_BMS, 0x40, 20)
    parsed = parse_packet(pkt)
    assert parsed["src"] == ADDR_PC
    assert parsed["dst"] == ADDR_BMS
    assert parsed["cmd"] == CMD_READ
    assert parsed["reg"] == 0x40
    assert parsed["data"] == bytes([20])


def test_build_read_cmd_different_registers():
    """build_read_cmd should work for various register addresses."""
    for reg, length in [(0x10, 14), (0x17, 2), (0x30, 2), (0x40, 20)]:
        pkt = build_read_cmd(ADDR_BMS, reg, length)
        parsed = parse_packet(pkt)
        assert parsed["valid"] is True
        assert parsed["reg"] == reg
        assert parsed["data"] == bytes([length])


def test_build_write_cmd():
    """Write 0x0001 to ESC register 0x78."""
    pkt = build_write_cmd(ADDR_ESC, 0x78, 0x0001)
    parsed = parse_packet(pkt)
    assert parsed["src"] == ADDR_PC
    assert parsed["dst"] == ADDR_ESC
    assert parsed["cmd"] == CMD_WRITE
    assert parsed["reg"] == 0x78
    assert parsed["data"] == b"\x01\x00"


def test_build_write_cmd_no_reply():
    """Write without reply should use CMD_WRITE_NO_REPLY."""
    pkt = build_write_cmd(ADDR_ESC, 0x78, 0x0001, with_reply=False)
    parsed = parse_packet(pkt)
    assert parsed["cmd"] == CMD_WRITE_NO_REPLY


def test_build_write_cmd_value_encoding():
    """Values should be encoded as U16 little-endian."""
    pkt = build_write_cmd(ADDR_BMS, 0x00, 0xABCD)
    parsed = parse_packet(pkt)
    assert parsed["data"] == b"\xCD\xAB"  # little-endian


def test_build_write_cmd_zero_value():
    """Writing zero should produce 0x00 0x00 data."""
    pkt = build_write_cmd(ADDR_BMS, 0x00, 0x0000)
    parsed = parse_packet(pkt)
    assert parsed["data"] == b"\x00\x00"


def test_build_write_bytes_cmd():
    """Write arbitrary bytes to a register."""
    data = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
    pkt = build_write_bytes_cmd(ADDR_ESC, 0x17, data)
    parsed = parse_packet(pkt)
    assert parsed["data"] == data
    assert parsed["reg"] == 0x17


def test_build_write_bytes_cmd_no_reply():
    """Write bytes without reply should use CMD_WRITE_NO_REPLY."""
    data = bytes([0x01, 0x02])
    pkt = build_write_bytes_cmd(ADDR_ESC, 0x17, data, with_reply=False)
    parsed = parse_packet(pkt)
    assert parsed["cmd"] == CMD_WRITE_NO_REPLY


def test_build_write_bytes_cmd_empty():
    """Writing empty bytes should still produce a valid packet."""
    pkt = build_write_bytes_cmd(ADDR_ESC, 0x17, b"")
    parsed = parse_packet(pkt)
    assert parsed["valid"] is True
    assert parsed["data"] == b""


def test_format_packet_hex():
    """format_packet_hex should contain header bytes in hex."""
    pkt = build_packet(ADDR_APP, ADDR_BMS, CMD_MCU_RESET, 0x00)
    hex_str = format_packet_hex(pkt)
    assert "5A" in hex_str.upper() or "5a" in hex_str
    assert "A5" in hex_str.upper() or "a5" in hex_str


def test_format_packet_hex_all_bytes_present():
    """Every byte of the packet should appear in the hex string."""
    pkt = build_packet(ADDR_APP, ADDR_BMS, CMD_READ, 0x40, bytes([20]))
    hex_str = format_packet_hex(pkt)
    parts = hex_str.split()
    assert len(parts) == len(pkt)


def test_format_packet_hex_uppercase():
    """Output should be uppercase hex."""
    pkt = build_packet(ADDR_APP, ADDR_BMS, CMD_READ, 0x40, bytes([0xAB]))
    hex_str = format_packet_hex(pkt)
    # The implementation uses uppercase
    assert "AB" in hex_str


# ============================================================================
# 6. Write Response Parsing Tests
# ============================================================================


def test_parse_write_response_success_from_data():
    """parse_write_response reads status from data[0]; WRITE_SUCCESS=0x00."""
    pkt = build_packet(
        ADDR_BMS, ADDR_APP, CMD_WRITE_RESP, 0x00,
        bytes([WRITE_SUCCESS]),
    )
    parsed = parse_packet(pkt)
    success, msg = parse_write_response(parsed)
    assert success is True
    assert "success" in msg.lower()


def test_parse_write_response_busy():
    """Busy error should report failure."""
    pkt = build_packet(
        ADDR_BMS, ADDR_APP, CMD_WRITE_RESP, 0x00,
        bytes([WRITE_ERR_BUSY]),
    )
    parsed = parse_packet(pkt)
    success, msg = parse_write_response(parsed)
    assert success is False
    assert "busy" in msg.lower()


def test_parse_write_response_size_error():
    """Size error should report failure."""
    pkt = build_packet(
        ADDR_BMS, ADDR_APP, CMD_WRITE_RESP, 0x00,
        bytes([WRITE_ERR_SIZE]),
    )
    parsed = parse_packet(pkt)
    success, msg = parse_write_response(parsed)
    assert success is False
    assert "size" in msg.lower()


def test_parse_write_response_format_error():
    """Format error should report failure."""
    pkt = build_packet(
        ADDR_BMS, ADDR_APP, CMD_WRITE_RESP, 0x00,
        bytes([WRITE_ERR_FORMAT]),
    )
    parsed = parse_packet(pkt)
    success, msg = parse_write_response(parsed)
    assert success is False
    assert "format" in msg.lower()


def test_parse_write_response_unknown_code():
    """Unknown error code should still report failure."""
    pkt = build_packet(
        ADDR_BMS, ADDR_APP, CMD_WRITE_RESP, 0x00,
        bytes([0xFF]),
    )
    parsed = parse_packet(pkt)
    success, msg = parse_write_response(parsed)
    assert success is False
    assert "unknown" in msg.lower() or "0xff" in msg.lower()


def test_parse_write_response_empty_data():
    """Empty data in write response should report failure."""
    pkt = build_packet(ADDR_BMS, ADDR_APP, CMD_WRITE_RESP, 0x00)
    parsed = parse_packet(pkt)
    success, msg = parse_write_response(parsed)
    assert success is False


# ============================================================================
# 7. Edge Case Tests
# ============================================================================


def test_build_packet_max_payload():
    """128-byte payload (firmware page) should roundtrip correctly."""
    data = bytes(range(128))
    pkt = build_packet(ADDR_APP, ADDR_BMS, CMD_IAP_TRANS, 0x00, data)
    parsed = parse_packet(pkt)
    assert parsed["valid"] is True
    assert parsed["data"] == data


def test_build_packet_all_zeros():
    """Packet with all-zero fields should still be valid."""
    pkt = build_packet(0x00, 0x00, 0x00, 0x00, b"\x00\x00")
    parsed = parse_packet(pkt)
    assert parsed["valid"] is True


def test_build_packet_all_0xff():
    """Packet with all-0xFF addresses/cmd/reg should still be valid."""
    pkt = build_packet(0xFF, 0xFF, 0xFF, 0xFF, b"\xFF\xFF")
    parsed = parse_packet(pkt)
    assert parsed["valid"] is True


def test_build_packet_255_byte_payload():
    """Maximum single-byte length field payload (255 bytes)."""
    data = bytes([0xAA] * 255)
    pkt = build_packet(ADDR_APP, ADDR_BMS, CMD_IAP_TRANS, 0x00, data)
    assert pkt[2] == 255
    parsed = parse_packet(pkt)
    assert parsed["valid"] is True
    assert parsed["data"] == data
    assert len(parsed["data"]) == 255


def test_parse_packet_extra_trailing_bytes():
    """Extra bytes after a valid packet should not prevent parsing."""
    pkt = build_packet(ADDR_APP, ADDR_BMS, CMD_READ, 0x40, bytes([20]))
    extended = pkt + b"\xFF\xFF\xFF"
    parsed = parse_packet(extended)
    # Should still parse the valid packet portion
    assert parsed is not None
    assert parsed["valid"] is True
    assert parsed["data"] == bytes([20])


def test_is_packet_complete_no_header():
    """Buffer with no valid header should return False."""
    buf = bytearray(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09")
    assert is_packet_complete(buf) is False


def test_extract_packet_only_garbage():
    """Buffer with only garbage (no header) should return None."""
    buf = bytearray(b"\x00\x01\x02\x03\x04\x05")
    extracted, remaining = extract_packet(buf)
    assert extracted is None


# ============================================================================
# 8. Constants Sanity Tests
# ============================================================================


def test_header_value():
    """Verify the protocol header is 0x5A 0xA5."""
    assert HEADER == b"\x5A\xA5"
    assert len(HEADER) == 2


def test_address_constants():
    """Verify all address constants match the Ninebot protocol spec."""
    assert ADDR_ESC == 0x20
    assert ADDR_BLE == 0x21
    assert ADDR_BMS == 0x22
    assert ADDR_EXT_BMS == 0x23
    assert ADDR_PC == 0x3D
    assert ADDR_APP == 0x3E


def test_command_constants():
    """Verify all command constants match the Ninebot protocol spec."""
    assert CMD_READ == 0x01
    assert CMD_WRITE == 0x02
    assert CMD_WRITE_NO_REPLY == 0x03
    assert CMD_READ_RESP == 0x04
    assert CMD_WRITE_RESP == 0x05
    assert CMD_CLEAR_ERROR == 0x06
    assert CMD_IAP_BEGIN == 0x07
    assert CMD_IAP_TRANS == 0x08
    assert CMD_IAP_VERIFY == 0x09
    assert CMD_MCU_RESET == 0x0A
    assert CMD_INIT == 0x5B
    assert CMD_PING == 0x5C
    assert CMD_PAIR == 0x5D


def test_write_error_constants():
    """Verify write error code constants."""
    assert WRITE_SUCCESS == 0x00
    assert WRITE_ERR_AUTH == 0x01
    assert WRITE_ERR_BUSY == 0x02
    assert WRITE_ERR_SIZE == 0x03
    assert WRITE_ERR_FORMAT == 0x04


# ============================================================================
# 9. Realistic Scenario Tests
# ============================================================================


def test_full_read_exchange_simulation():
    """Simulate a complete read exchange: request then response.

    APP sends CMD_READ to BMS for register 0x34 (voltage).
    BMS responds with CMD_READ_RESP containing voltage data.
    """
    # Step 1: Build request
    request = build_read_cmd(ADDR_BMS, 0x34, 2)
    req_parsed = parse_packet(request)
    assert req_parsed["src"] == ADDR_PC
    assert req_parsed["dst"] == ADDR_BMS
    assert req_parsed["cmd"] == CMD_READ
    assert req_parsed["reg"] == 0x34

    # Step 2: Build simulated response (36.50V = 3650 in 10mV units)
    voltage_raw = (3650).to_bytes(2, "little")
    response = build_packet(ADDR_BMS, ADDR_PC, CMD_READ_RESP, 0x34, voltage_raw)
    resp_parsed = parse_packet(response)
    assert resp_parsed["valid"] is True
    assert resp_parsed["cmd"] == CMD_READ_RESP
    voltage = int.from_bytes(resp_parsed["data"], "little")
    assert voltage == 3650


def test_full_write_exchange_simulation():
    """Simulate a write exchange: request then success response."""
    # Step 1: Write command
    request = build_write_cmd(ADDR_ESC, 0x78, 0x0001)
    req_parsed = parse_packet(request)
    assert req_parsed["cmd"] == CMD_WRITE

    # Step 2: Simulated success response
    response = build_packet(
        ADDR_ESC, ADDR_APP, CMD_WRITE_RESP, 0x00,
        bytes([WRITE_SUCCESS]),
    )
    resp_parsed = parse_packet(response)
    success, msg = parse_write_response(resp_parsed)
    assert success is True


def test_streaming_reassembly():
    """Simulate bytes arriving in small chunks via BLE notifications.

    Build two packets, fragment them into small chunks, feed into
    extract_packet to verify reassembly works.
    """
    pkt1 = build_packet(ADDR_BMS, ADDR_APP, CMD_READ_RESP, 0x40, bytes(20))
    pkt2 = build_packet(ADDR_BMS, ADDR_APP, CMD_READ_RESP, 0x34, bytes(2))

    full_stream = bytearray(pkt1) + bytearray(pkt2)

    # Simulate chunked arrival (3-byte chunks)
    buf = bytearray()
    extracted_packets = []
    chunk_size = 3

    for i in range(0, len(full_stream), chunk_size):
        buf += full_stream[i : i + chunk_size]
        while True:
            pkt, buf = extract_packet(buf)
            if pkt is None:
                break
            extracted_packets.append(pkt)

    assert len(extracted_packets) == 2
    assert extracted_packets[0] == pkt1
    assert extracted_packets[1] == pkt2


def test_build_read_cmd_matches_manual_build():
    """build_read_cmd should produce identical output to manual build_packet."""
    manual = build_packet(ADDR_PC, ADDR_BMS, CMD_READ, 0x40, bytes([20]))
    convenience = build_read_cmd(ADDR_BMS, 0x40, 20)
    assert manual == convenience


def test_build_write_cmd_matches_manual_build():
    """build_write_cmd should produce identical output to manual build_packet."""
    import struct as st
    manual = build_packet(ADDR_PC, ADDR_ESC, CMD_WRITE, 0x78, st.pack("<H", 0x0001))
    convenience = build_write_cmd(ADDR_ESC, 0x78, 0x0001)
    assert manual == convenience
