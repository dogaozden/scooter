# Context Doc: Ninebot F2 Pro BMS Cell Voltage Diagnostic Tool

## Goal
Build a Python CLI tool that connects to a Segway Ninebot F2 Pro electric scooter over Bluetooth Low Energy (BLE) and reads individual cell group voltages from the Battery Management System (BMS). This is a READ-ONLY diagnostic tool. Do NOT write any data to the scooter.

## Why
The scooter's BMS firmware (V1.3.4) is cutting off charging at 23% due to detected cell imbalance. We need to read the voltage of each of the 10 series cell groups to determine which cells are low and how severe the imbalance is. The owner has an iPhone and can't use Android-only diagnostic apps (ScooterHacking Utility, Nine Dash, XiaoDash), so we're building a laptop-based tool.

## Scooter Details
- **Model**: Segway Ninebot F2 Pro
- **Serial**: NAGSF2430C0153  
- **Battery serial**: 16DGJ24G2F0712
- **BMS firmware**: V1.3.4
- **Battery config**: 10S (10 series cell groups), 36V nominal, 460Wh, 12800mAh total
- **Current state**: 15% charge, 35.6V pack voltage, not accepting charge above 23%
- **Battery health**: 95.8% (12262/12800 mAh), 85 charge cycles

## Protocol Documentation

### Communication Architecture
The Ninebot F2 series uses the "Ninebot" protocol variant (not Xiaomi/M365):

```
Phone --> BLE (Bluetooth LE) --> BLE module --> ESC --> BMS
```

The phone talks to the BLE module, which forwards to the ESC, which forwards to the BMS. All communication is packet-based over BLE.

### BLE Service/Characteristic
Ninebot scooters expose:
- **Service UUID**: `FFE0` (or a Ninebot-specific UUID)
- **Characteristic UUID**: `FFE1` (Read, Write Without Response, Notify)

Commands are written to FFE1, responses come back as notifications on FFE1.

### Ninebot Packet Format
```
5A A5 bLen bSrcAddr bDstAddr bCmd bArg bPayload[bLen] wChecksumLE
```

Fields:
- `5A A5` — Magic header bytes
- `bLen` — Length of bPayload (just the payload, not including other fields)
- `bSrcAddr` — Source address
- `bDstAddr` — Destination address
- `bCmd` — Command byte
- `bArg` — Argument (register offset for read commands)
- `bPayload[]` — Payload data
- `wChecksumLE` — Little-endian checksum: `0xFFFF XOR (16-bit sum of bytes: bSrcAddr, bDstAddr, bCmd, bArg, bPayload[])`

### Address Bytes
- `0x20` — ESC
- `0x21` — BLE
- `0x22` — BMS (internal)
- `0x23` — External BMS
- `0x3E` or `0x3F` — Application (phone/client)

### Read Register Command
To read BMS registers from the phone/app:
- `bSrcAddr`: `0x3E` (application)
- `bDstAddr`: `0x22` (BMS)
- `bCmd`: `0x01` (read registers)
- `bArg`: register offset (in 16-bit words)
- `bPayload`: `[length]` — number of bytes to read

Response will have:
- `bCmd`: `0x04` (read response for Ninebot protocol)
- `bArg`: register offset echoed back
- `bPayload`: the register data

### Known BMS Register Map (Ninebot ES/Max series, likely similar for F2)
Based on community reverse engineering (etransport/ninebot-docs, ScooterHacking wiki):

| Register (hex) | Size | Description |
|---|---|---|
| 0x00 | U16 | Magic identifier |
| 0x10 | 14B | BMS serial number |
| 0x17 | U16 | BMS firmware version |
| 0x18 | U16 | Total capacity (mAh) |
| 0x19 | U16 | ? |
| 0x1A | U16 | ? |
| 0x22 | U16 | Remaining capacity (mAh) |
| 0x23 | U16 | Remaining percent |
| 0x24 | U16 | Current (signed, mA) |
| 0x25 | U16 | Voltage (mV) — total pack |
| 0x26 | U16 | Temperature 1 (0.1°C) |
| 0x27 | U16 | Temperature 2 (0.1°C) |
| 0x2A | U16 | Health / remaining capacity |
| 0x30-0x39 | U16 each | **Cell group voltages** (10 cells for 10S) |
| 0x3B | U16 | Charge cycles |

**CRITICAL**: The cell voltage registers are the primary target. For a 10S pack, registers 0x30 through 0x39 should each contain a U16 value representing individual cell group voltage in millivolts.

**WARNING**: These register addresses are based on the ES/Max series and may differ on the F2. The tool should attempt to read a range and identify which registers contain plausible cell voltage values (expect values between 2500-4250, representing 2.5V-4.25V in mV).

## Implementation Requirements

### Dependencies
- `bleak` — Cross-platform Python BLE library (works on macOS, Windows, Linux)
- Python 3.8+

### Core Functionality

1. **Scan and Connect**: Scan for nearby BLE devices, filter for Ninebot scooters (device name typically starts with "Ninebot" or contains the serial number), connect to the scooter.

2. **Build Ninebot Packets**: Implement the packet format above with proper checksum calculation.

3. **Read BMS Registers**: Send read commands targeting BMS (addr 0x22) and parse responses.

4. **Read Cell Voltages**: Read registers 0x30-0x39 (and nearby ranges as fallback) to get individual cell group voltages.

5. **Display Results**: Print a clear table showing:
   - Each cell group number (1-10)
   - Voltage in V (convert from mV)
   - Delta from highest cell
   - Flag any cells that deviate more than 100mV from the average

6. **Also read general BMS info**: Total voltage, current, temperature, remaining capacity, BMS firmware version, charge cycles — to cross-reference with what the app shows.

### Checksum Implementation
```python
def calc_checksum(data):
    """Calculate Ninebot protocol checksum.
    data = bytes of [bSrcAddr, bDstAddr, bCmd, bArg, *bPayload]
    Returns 2-byte little-endian checksum.
    """
    s = sum(data) & 0xFFFF
    checksum = 0xFFFF ^ s
    return checksum.to_bytes(2, 'little')
```

### Packet Builder
```python
def build_ninebot_packet(src, dst, cmd, arg, payload=b''):
    """Build a complete Ninebot protocol packet.
    Returns bytes ready to write to BLE characteristic.
    """
    header = bytes([0x5A, 0xA5])
    blen = len(payload)
    core = bytes([src, dst, cmd, arg]) + payload
    checksum = calc_checksum(core)
    return header + bytes([blen]) + core + checksum
```

### Reading BMS Registers
```python
# Example: Read 10 cell voltages starting at register 0x30
# Each register is U16 (2 bytes), so read 20 bytes
packet = build_ninebot_packet(
    src=0x3E,   # Application
    dst=0x22,   # BMS
    cmd=0x01,   # Read register
    arg=0x30,   # Starting register offset
    payload=bytes([20])  # Read 20 bytes (10 x U16)
)
```

### BLE Communication Pattern with bleak
```python
import asyncio
from bleak import BleakClient, BleakScanner

UART_SERVICE = "0000ffe0-0000-1000-8000-00805f9b34fb"  # May vary
UART_CHAR = "0000ffe1-0000-1000-8000-00805f9b34fb"     # May vary

# Also try the Ninebot-specific UUIDs if FFE0/FFE1 don't work:
# Service: "6e400001-b5a3-f393-e0a9-e50e24dcca9e" (Nordic UART)
# RX: "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
# TX: "6e400003-b5a3-f393-e0a9-e50e24dcca9e"
```

### Important Notes

1. **BLE encryption**: Newer Ninebot firmware may require authentication/pairing. The F2 Pro with BMS V1.3.4 may need the scooter to be powered on and the official app disconnected before our tool can connect.

2. **Fragmentation**: BLE packets may be fragmented across multiple notifications. Accumulate bytes until you have a complete packet (check for 5A A5 header and verify length).

3. **Response routing**: The BMS response comes back through the ESC and BLE module. The response packet will have `bSrcAddr=0x22` (BMS) and `bDstAddr=0x3E` (application).

4. **F2 series differences**: The F2 uses a newer BLE/ESC architecture than the ES series. If the standard register addresses don't work, try:
   - Reading ESC registers first (dst=0x20) to confirm communication works
   - Scanning a wider range of BMS registers (0x00-0x50) to map the register layout
   - The F2 may use different cell voltage register offsets

5. **READ ONLY**: This tool must NEVER write to any register. Only use cmd=0x01 (read). Never use cmd=0x02 or 0x03 (write).

6. **Fallback discovery mode**: If known registers don't return expected values, implement a register scanner that reads registers 0x00 through 0x50 from the BMS and dumps all values. We can then manually identify which registers contain cell voltages (they'll be U16 values in the 2500-4250 range for millivolts, or 250-425 range for centimillivolts).

## Reference Repositories
- `github.com/etransport/py9b` — Ninebot/Xiaomi communication library (Python, GPL-3.0). Has BLE transport, packet handling, and firmware flashing. Study the transport and command layers but don't use the flashing code.
- `github.com/etransport/ninebot-docs` — Protocol wiki with register maps
- `github.com/etransport/PySWIM` — STM8 SWIM library, includes BMS tester code that reads cell voltages over UART

## Expected Output
```
=== Ninebot F2 Pro BMS Diagnostic ===
Serial: 16DGJ24G2F0712
Firmware: V1.3.4
Pack Voltage: 35.6V
Current: 0.0A
Temperature: 18°C
Remaining: 3059 mAh / 12800 mAh (23%)
Charge Cycles: 85

=== Cell Group Voltages ===
Cell  1: 3.89V  (delta: +0.32V) ⚠️ HIGH
Cell  2: 3.72V  (delta: +0.15V)
Cell  3: 3.68V  (delta: +0.11V)
Cell  4: 3.57V  (delta: +0.00V)  [reference]
Cell  5: 3.58V  (delta: +0.01V)
Cell  6: 3.42V  (delta: -0.15V) ⚠️ LOW
Cell  7: 3.21V  (delta: -0.36V) ⚠️ LOW — NEEDS BALANCING
Cell  8: 3.55V  (delta: -0.02V)
Cell  9: 3.50V  (delta: -0.07V)
Cell 10: 3.48V  (delta: -0.09V)

Pack Total: 35.60V
Max Delta: 0.68V ⚠️ SEVERE IMBALANCE
Cells needing balance charge: 6, 7
```

(The above is example output — actual values will differ.)

## What to Do With Results
Once we have the cell voltages, we can determine:
1. How many cells are low and by how much
2. Whether any cells are dead (voltage < 2.5V = unrecoverable)
3. Whether passive balancing (leaving charger plugged in 72hrs) might work (delta < 0.3V)
4. Whether manual cell balancing is needed (delta > 0.3V)
5. Whether any cells are swelling/dangerous (voltage spikes to 4.2V instantly = high internal resistance)
