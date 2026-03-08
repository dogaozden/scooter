# Ninebot F2 Pro BLE/BMS Protocol Research Findings

## Table of Contents
1. [Packet Format](#1-packet-format)
2. [Device Addresses](#2-device-addresses)
3. [Command Types](#3-command-types)
4. [BLE Transport Layer](#4-ble-transport-layer)
5. [Authentication / Encryption](#5-authentication--encryption)
6. [BMS Register Map (Complete)](#6-bms-register-map-complete)
7. [ESC Register Map (Key Registers)](#7-esc-register-map-key-registers)
8. [Read Command Format](#8-read-command-format)
9. [Write Command Format](#9-write-command-format)
10. [Write Error Codes](#10-write-error-codes)
11. [BMS Status Flags (BAT_FUN_BOOLEAN 0x30)](#11-bms-status-flags)
12. [Error Codes](#12-error-codes)
13. [Checksum Calculation](#13-checksum-calculation)
14. [Existing Python Libraries](#14-existing-python-libraries)
15. [F2 Pro Specific Notes](#15-f2-pro-specific-notes)
16. [Write Strategy for BMS Reset/Fix](#16-write-strategy-for-bms-resetfix)

---

## 1. Packet Format

Source: Official Ninebot ES Communication Protocol Document (nbdoc.pdf), released by ScooterHacking.org.

```
5A A5 bLen bSrcAddr bDstAddr bCmd bDataIndex bDataSegment[N] wChecksumLE
```

| Field | Size | Description |
|-------|------|-------------|
| Frame header | 2 bytes | Always `0x5A 0xA5` |
| Packet length (bLen) | 1 byte | Length of data segment only (N bytes) |
| Source ID | 1 byte | Who is sending |
| Target ID | 1 byte | Who is receiving |
| Command word | 1 byte | Operation type (read/write/etc) |
| Data index | 1 byte | Register offset address |
| Data segment | N bytes | Payload (variable length) |
| Checksum | 2 bytes | Little-endian, covers all bytes except header |

**Key facts:**
- Basic storage unit of the memory control table is 2 bytes (signed 16-bit integer / short)
- All multi-byte data is little-endian
- Serial port: 115200 baud, 8 bits, no parity, 1 stop bit
- BLE messages are chunked into 20-byte fragments

---

## 2. Device Addresses

| Address | Device | Notes |
|---------|--------|-------|
| `0x20` | ESC (Master controller) | Main scooter controller |
| `0x21` | BLE module | Bluetooth instrument panel |
| `0x22` | Internal BMS | Built-in battery |
| `0x23` | External BMS | External battery (if present) |
| `0x3D` | PC / Upper computer | Serial/CAN debugger, IoT equipment |
| `0x3E` | Mobile phone / App | Via Bluetooth serial port |
| `0x00` | Broadcast | Entire network |

**For BMS communication from phone:**
- Source: `0x3E` (phone/app)
- Destination: `0x22` (internal BMS)

**Important:** To talk to the external BMS, you still address `0x22` -- the ESC redirects internally. Using `0x23` directly does NOT work (confirmed in py9b issue #4).

---

## 3. Command Types

### Control Table Access

| Command | Value | Function | Data Segment | Response |
|---------|-------|----------|--------------|----------|
| CMD_CMAP_RD | `0x01` | Read register(s) | 1 byte: read length in bytes | Response: `0x04` |
| CMD_CMAP_WR | `0x02` | Write register(s), WITH reply | 0~N bytes: write data | Response: `0x05` |
| CMD_CMAP_WR_NR | `0x03` | Write register(s), WITHOUT reply | 0~N bytes: write data | None |
| CMD_CMAP_ACK_RD | `0x04` | Read response | 0~N bytes: data read | N/A |
| CMD_CMAP_ACK_WR | `0x05` | Write response | 0 bytes (result in data_index) | N/A |

### Firmware Download

| Command | Value | Function |
|---------|-------|----------|
| CMD_IAP_BEGIN | `0x07` | Start firmware download (4-byte size) |
| CMD_IAP_TRANS | `0x08` | Firmware data block |
| CMD_IAP_VERIFY | `0x09` | Verify firmware checksum (4-byte checksum) |
| CMD_MCU_RESET | `0x0A` | Chip reset (no reply) |

### Special Commands

| Command | Value | Function |
|---------|-------|----------|
| INIT | `0x5B` | Request device info (returns key + serial) |
| PING | `0x5C` | Key exchange / pairing ping |
| PAIR | `0x5D` | Complete pairing with serial number |
| CMD_SCO_HEARTBEAT | `0x55` | Heartbeat (index=0x7C, data=0x7C every 30s or motor locks) |

---

## 4. BLE Transport Layer

### Service and Characteristics

| Component | UUID |
|-----------|------|
| Nordic UART Service | `6e400001-b5a3-f393-e0a9-e50e24dcca9e` |
| RX Characteristic (write to scooter) | `6e400002-b5a3-f393-e0a9-e50e24dcca9e` |
| TX Characteristic (notify from scooter) | `6e400003-b5a3-f393-e0a9-e50e24dcca9e` |

**Protocol:**
1. Subscribe to notifications on TX characteristic (`6e400003...`)
2. Write commands to RX characteristic (`6e400002...`)
3. Messages > 20 bytes must be fragmented into 20-byte chunks
4. Reassemble incoming notification fragments (first fragment starts with `5A A5`)

### Xiaomi GATT Service (for auth)
Some newer models also expose:
- Service `0xFE95` with UPNP (`0x0010`) and AVDTP (`0x0019`) characteristics for pairing/session

---

## 5. Authentication / Encryption

### NinebotCrypto Protocol (used by F-series / F2 Pro)

The F2 Pro uses the **NinebotCrypto** protocol, NOT the Mi/Xiaomi auth protocol. This is confirmed by the `ninebot-ble` library which was developed specifically against an F-series scooter.

**Crypto primitives:**
- **SHA-1** for key derivation (first 16 bytes of SHA-1 hash)
- **AES-128-ECB** for encryption
- **CRC-16** (bitwise NOT of sum) for checksums

**Key constants:**
- `FW_DATA = 0x97CFB802844143DE56002B3B34780A5D` (hardcoded firmware key)

### Pairing / Authentication Sequence

```
1. CONNECT to BLE device

2. INIT: Send cmd=0x5B to BLE module (src=0x3E, dst=0x21)
   - No payload
   - Response contains: 16-byte BLE key + 14-byte serial number
   - Initial SHA1 key = SHA1(device_name + FW_DATA)[:16]

3. PING: Send cmd=0x5C (src=0x3E, dst=0x21) with 16 random bytes (APP_KEY)
   - If response data_index == 0: NOT YET PAIRED, need button press
   - If response data_index == 1: ALREADY PAIRED

4. If not paired:
   - Send cmd=0x5D (PAIR) with the serial number received in step 2
   - User must press power button on scooter
   - Wait for response with data_index == 1
   - Update SHA1 key = SHA1(APP_KEY + BLE_KEY)[:16]

5. PAIR: Send cmd=0x5D with serial number to finalize
   - Response confirms: data_index == 1

6. Session established. All subsequent packets are encrypted/decrypted.
```

### Encryption Format

After authentication, every packet is encrypted:

```
[5A A5] [encrypted_payload] [4-byte CRC-MAC] [2-byte iteration counter]
```

- First 3 bytes (header) pass through unencrypted
- Payload is XORed with AES-ECB output using iteration counter
- CRC-MAC provides message authentication
- Iteration counter increments with each sent message

### Decryption

```python
# Iteration counter is in last 2 bytes of received message
it = (data[-2] << 8) + data[-1]
# Generate AES counter block from iteration + BLE key
# XOR encrypted payload with AES keystream
```

---

## 6. BMS Register Map (Complete)

Source: Official nbdoc.pdf, Section 5 "Description of battery memory control"

All offsets are in 16-bit word units. Each register is 2 bytes (S16 or U16) unless noted otherwise.

### Identity / Configuration Registers

| Address | Name | Description | Type | R/W | Initial |
|---------|------|-------------|------|-----|---------|
| 0x00-0x0F | Reserved | Reserved | -- | -- | -- |
| 0x10-0x16 | BAT_SN | Battery serial number, 14 bytes | 7x U8 pairs | R | -- |
| 0x17 | BAT_SW_VER | Battery hardware and firmware version | U16 | R | 0 |
| 0x18 | BAT_CAPACITY | Design capacity of the battery, mAh | U16 | R | 0 |
| 0x19 | BAT_TOTAL_CAPACITY | Full charge capacity of the battery, mAh | U16 | R | 0 |
| 0x1A | BAT_DESIGN_VOLTAGE | Design voltage of the battery, 10mV | U16 | R | 0 |
| 0x1B | BAT_CYCLE_TIMES | Cycle times of the battery | U16 | R | 0 |
| 0x1C | BAT_CHARGE_TIMES | Battery charging times | U16 | R | 0 |
| 0x1D | BAT_CHARGE_CAP_L | Accumulative charge capacity, lower 16 bits, 10mAh | U16 | R | 0 |
| 0x1E | BAT_CHARGE_CAP_H | Accumulative charge capacity, higher 16 bits, 10mAh | U16 | R | 0 |
| 0x1F | BAT_OVER_DISCHARGE_TIMES | Overflow + over-discharge times (lower 8 = overflow, upper 8 = over-discharge) | U16 | R | 0 |
| 0x20-0x2F | Reserved | Reserved | U16 | R | -- |

### Status / Live Measurement Registers

| Address | Name | Description | Type | R/W |
|---------|------|-------------|------|-----|
| 0x30 | BAT_FUN_BOOLEAN | Boolean status variable (see bit flags below) | S16 | **see flags** |
| 0x31 | BAT_REMAINING_CAP | Current residual capacity, mAh | U16 | R |
| 0x32 | BAT_REMAINING_CAP_PERCENT | Current residual capacity percentage, 0-100 | S16 | R |
| 0x33 | BAT_CURRENT_CUR | Current current, 10mA (positive=discharge, negative=charge) | S16 | R |
| 0x34 | BAT_VOLTAGE_CUR | Current voltage, 10mV | S16 | R |
| 0x35 | BAT_TEMP_CUR | Temperature: high byte = sensor 2, low byte = sensor 1. Range 0-119 maps to -20C to 99C | S16 | R |
| 0x36 | BAT_BALANCE_STATU | Balanced open status of the protective plate (bitmap) | S16 | R |
| 0x37 | BAT_ODIS_STATE | Undervoltage condition of battery cell (bitmap) | S16 | R |
| 0x38 | BAT_OCHG_STATE | Overvoltage condition of battery cell (bitmap) | S16 | R |
| 0x39 | BAT_CAP_COULO | Coulombmeter capacity | S16 | R |
| 0x3A | BAT_CAP_VOL | Voltmeter capacity | S16 | R |
| 0x3B | BAT_HEALTHY | Health degree, 0-100% | S16 | R |
| 0x3C-0x3F | Reserved | Reserved | S16 | R |

### Cell Voltage Registers

| Address | Name | Description | Type | R/W |
|---------|------|-------------|------|-----|
| 0x40 | BAT_CORE_VOLT_1 | Cell 1 voltage, mV | S16 | R |
| 0x41 | BAT_CORE_VOLT_2 | Cell 2 voltage, mV | S16 | R |
| 0x42 | BAT_CORE_VOLT_3 | Cell 3 voltage, mV | S16 | R |
| 0x43 | BAT_CORE_VOLT_4 | Cell 4 voltage, mV | S16 | R |
| 0x44 | BAT_CORE_VOLT_5 | Cell 5 voltage, mV | S16 | R |
| 0x45 | BAT_CORE_VOLT_6 | Cell 6 voltage, mV | S16 | R |
| 0x46 | BAT_CORE_VOLT_7 | Cell 7 voltage, mV | S16 | R |
| 0x47 | BAT_CORE_VOLT_8 | Cell 8 voltage, mV | S16 | R |
| 0x48 | BAT_CORE_VOLT_9 | Cell 9 voltage, mV | S16 | R |
| 0x49 | BAT_CORE_VOLT_10 | Cell 10 voltage, mV | S16 | R |
| 0x4A-0x4F | BAT_CORE_VOLT_11-16 | Cells 11-16 (if present, for 13S+ packs) | S16 | R |

**For F2 Pro (10S configuration): Only registers 0x40-0x49 are relevant.**

---

## 7. ESC Register Map (Key Registers)

### Read-only Status Registers (on ESC, address 0x20)

| Address | Name | Description | R/W |
|---------|------|-------------|-----|
| 0x10-0x16 | NB_INF_SN | Scooter serial number, 14 bytes | R |
| 0x17-0x19 | NB_INF_BTPASSWORD | Bluetooth pairing code, 6 bytes | R/W |
| 0x1A | NB_INF_FW_VERSION | Controller firmware version | R |
| 0x1B | NB_INF_ERROR | Error code | R |
| 0x1C | NB_INF_ALERM | Alarm code | R |
| 0x1D | NB_INF_BOOL | Boolean state word (bit flags) | R |
| 0x22 | NB_INF_BTC | Battery percentage, 0-100 | R |
| 0x26 | NB_INF_SPEED | Current speed, 0.1 km/h | R |
| 0x3E | NB_INF_BODY_TEMP | Scooter temperature, 0.1C | R |
| 0x67 | NB_INF_VER_BMS | Built-in BMS firmware version | R |
| 0x68 | NB_INF_VER_BLE | BLE firmware version | R |

### Writable Control Registers (on ESC, address 0x20)

| Address | Name | Description | R/W | Default |
|---------|------|-------------|-----|---------|
| 0x70 | NB_CTL_LOCK | Lock scooter (write 1) | R/W | 0 |
| 0x71 | NB_CTL_UNLOCK | Unlock scooter (write 1) | R/W | 0 |
| 0x72 | NB_CTL_LIMIT_SPD | Speed limit or release | R/W | 250 |
| 0x73 | NB_CTL_NOMALSPEED | Speed limit value in normal mode, 0.1km/h | R/W | 150 |
| 0x74 | NB_CTL_LITSPEED | Speed limit value in speed limit mode, 0.1km/h | R/W | 60 |
| 0x75 | NB_CTL_WORKMODE | Operating mode: 0=NORMAL, 1=ECO, 2=SPORT | R/W | 0 |
| 0x77 | NB_CTL_ENGINE | Start/shut down engine | R/W | 0 |
| 0x78 | NB_CTL_REBOOT | Restart system (write 1) | R/W | 0 |
| 0x79 | NB_CTL_POWEROFF | Shutdown (write 1) | R/W | 0 |
| 0x7C | NB_CTL_CRUISE | Cruise control: 0=off, 1=on | R/W | 0 |
| 0x80 | NB_CTL_FUN_BOOL_1 | Function setup boolean 1 (see bit flags) | R/W | 0 |
| 0x81 | NB_CTL_FUN_BOOL_2 | Function setup boolean 2 (see bit flags) | R/W | 0 |
| 0x90 | NB_CTL_HEADLIGHT_IOT_SW | Headlight on/off | R/W | 1 |
| 0x91 | NB_CTL_BEEP_ALARM_SW | Beep alarm on/off | R/W | 1 |

---

## 8. Read Command Format

### Request (Phone -> Device)

```
5A A5 [len] [src] [dst] [0x01] [register_offset] [bytes_to_read]
```

**Example: Read scooter body temperature (register 0x3E on ESC)**
```
5A A5 01 3D 20 01 3E 02
       |  |  |  |  |  └─ read 2 bytes (1 register)
       |  |  |  |  └──── register 0x3E
       |  |  |  └─────── cmd 0x01 (read)
       |  |  └────────── dst 0x20 (ESC)
       |  └───────────── src 0x3D (PC)
       └──────────────── data segment length = 1
(+ 2-byte checksum at end, not shown - added by crypto layer)
```

### Response (Device -> Phone)

```
5A A5 [len] [dst_becomes_src] [src_becomes_dst] [0x04] [register_offset] [data...]
```

**Example: Temperature response = 31.8C (318 = 0x013E)**
```
5A A5 02 20 3D 04 3E 36 01
       |  |  |  |  |  └──── data: 0x0136 = 310 -> 31.0C (little-endian)
       |  |  |  |  └─────── register 0x3E (same as requested)
       |  |  |  └────────── cmd 0x04 (read response)
       |  |  └───────────── dst 0x3D (back to PC)
       |  └────────────────src 0x20 (from ESC)
       └───────────────── data segment length = 2
```

### Multi-register Read (14-byte serial number)

```
5A A5 01 3D 20 01 10 0E    <- read 14 bytes starting at register 0x10
```

### Read BMS Cell Voltages (all 10 cells)

```
5A A5 01 3E 22 01 40 14    <- read 20 bytes (10 x 2 bytes) starting at register 0x40
       |  |  |  |  |  └─── 0x14 = 20 bytes
       |  |  |  |  └────── register 0x40 (first cell)
       |  |  |  └───────── cmd 0x01 (read)
       |  |  └──────────── dst 0x22 (internal BMS)
       |  └───────────────  src 0x3E (phone)
       └──────────────── data segment length = 1
```

---

## 9. Write Command Format

### Write with Response (cmd=0x02)

```
5A A5 [len] [src] [dst] [0x02] [register_offset] [data_bytes...]
```

**Example: Write speed limit = 10 km/h to register 0x74 on ESC**

Value 10 km/h * 10 = 100 = 0x0064 (little-endian: 0x64 0x00)

```
5A A5 02 3D 20 03 74 64 00
       |  |  |  |  |  └──── data: 0x0064 = 100 (10.0 km/h)
       |  |  |  |  └─────── register 0x74
       |  |  |  └────────── cmd 0x03 (write without reply, shown; 0x02 for with reply)
       |  |  └───────────── dst 0x20 (ESC)
       |  └────────────────  src 0x3D (PC)
       └──────────────── data segment length = 2
```

### Write Response (from scooter, cmd=0x05)

```
5A A5 01 20 3D 05 74 01     <- success: data_index=0x74 (register), data=0x01 (success)
```

**Write response data_index meanings:**
- `0x00` = Write successful
- `0x01` = CMD_CMAP_WRERROR_AUTH - No write permission for the address
- `0x02` = CMD_CMAP_WRERROR_BUSY - Control table under operation, no write allowed
- `0x03` = CMD_CMAP_WRERROR_SIZE - Write data out of scope
- `0x04` = CMD_CMAP_WRERROR_FORM - Write data in wrong form

### Multi-register Write (Bluetooth pairing code)

```
5A A5 06 3D 20 03 17 01 02 03 04 05 06    <- write "123456" to register 0x17
```

### Write to BMS Register (general format)

```
5A A5 [len] 3E 22 02 [register] [data_lo] [data_hi]
```

---

## 10. Write Error Codes

When writing with cmd=0x02, the response packet (cmd=0x05) contains the result:

| data_index | Name | Meaning |
|------------|------|---------|
| 0x00 | Success | Write completed successfully |
| 0x01 | CMD_CMAP_WRERROR_AUTH | **No write permission** for this address |
| 0x02 | CMD_CMAP_WRERROR_BUSY | Control table busy, write rejected |
| 0x03 | CMD_CMAP_WRERROR_SIZE | Data size out of scope |
| 0x04 | CMD_CMAP_WRERROR_FORM | Data format wrong |

---

## 11. BMS Status Flags (BAT_FUN_BOOLEAN register 0x30)

| Bit | Mask | Name | Description |
|-----|------|------|-------------|
| 0 | 0x0001 | BMS_BOOLMARK_PASSWORD | Battery check code right or not |
| 1 | 0x0002 | BMS_BOOLMARK_ACT | Battery activated or not |
| 2 | 0x0004 | BMS_BOOLMARK_CHG_PROTECT | Battery charging protected or not |
| 3 | 0x0008 | BMS_BOOLMARK_CMOS | Charging MOS pipe open or not |
| 4 | 0x0010 | BMS_BOOLMARK_WRITE_CMD | **Write lock open or not** |
| 5 | 0x0020 | BMS_BOOLMARK_DISCHARGE | Discharging or not |
| 6 | 0x0040 | BMS_BOOLMARK_CHARGE | Charging or not |
| 7 | 0x0080 | BMS_BOOLMARK_CHARGERIN | Charger inserted or not |
| 8 | 0x0100 | BMS_BOOLMARK_DISOVER | Over discharging or not |
| 9 | 0x0200 | BMS_BOOLMARK_CHGOVER | Over charging or not |
| 10 | 0x0400 | BMS_BOOLMARK_VOERTEMP | Over temperature or not |
| 11 | 0x0800 | BMS_BOOLMARK_TEST_MODE | Test mode or not |

**CRITICAL: Bit 4 (BMS_BOOLMARK_WRITE_CMD, mask 0x0010) controls whether BMS write operations are allowed.** This flag likely needs to be set before writing to configuration registers on the BMS.

---

## 12. Error Codes

### BMS-Related Error Codes (from ESC register 0x1B)

| Code | Description |
|------|-------------|
| 16 | Built-in battery MOS switch abnormality |
| 17 | External battery MOS switch abnormality |
| 19 | Built-in battery voltage detection abnormality |
| 20 | External battery voltage detection abnormality |
| 21 | Built-in battery communication error (BMS <-> ESC) |
| 22 | Built-in battery password is wrong (BMS config invalid) |
| 23 | Built-in battery has default serial number (not activated) |
| 24 | System voltage detection abnormality |

### Extended Error Codes (from ScooterHacking wiki)

| Code | Description | Severity |
|------|-------------|----------|
| 21 | No communication with internal BMS | 2 |
| 22 | Internal BMS config invalid | 1 |
| 23 | Internal BMS not activated (default S/N) | 1 |
| 42 | No communication with external BMS | 3 |
| 45 | Internal BMS deep cell discharge | 3 |
| 47 | Internal battery protection board damaged | 3 |
| 49 | Internal BMS firmware version mismatch | 2 |

---

## 13. Checksum Calculation

From the official documentation and source code:

```c
uint16_t CheckSum1ByteIn2ByteOut(uint8_t* data, int len) {
    uint16_t checksum = 0;
    for (int i = 0; i < len; i++) {
        checksum += data[i];
    }
    checksum = ~checksum;  // bitwise NOT
    return checksum;
}
```

**In Python (from miauth/util.py):**

```python
def crc16(arr):
    n = ~sum(arr)
    return int_to_bytes(n, 2)  # returns 2 bytes, little-endian
```

**Scope:** Checksum covers ALL bytes EXCEPT the 2-byte header (`5A A5`). That is: `bLen + bSrcAddr + bDstAddr + bCmd + bDataIndex + bDataSegment[N]`.

**NOTE:** When NinebotCrypto encryption is active, the checksum is replaced by a 4-byte AES-CBC-MAC, and a 2-byte iteration counter is appended. The crypto layer handles this transparently.

---

## 14. Existing Python Libraries

### ninebot-ble (v0.0.6) - RECOMMENDED

- **PyPI:** `pip install ninebot-ble`
- **GitHub:** https://github.com/ownbee/ninebot-ble
- **Tested on:** Ninebot F-series scooter specifically
- **Auth:** Uses NinebotCrypto via miauth library
- **Features:** Full read support for BMS and ESC registers, BLE connection management, encryption
- **Limitation:** Only implements `read_reg()`, NO write_reg() method (but the infrastructure is there)

Key classes in `ninebot_ble/transport.py`:
- `Packet` class for constructing/parsing protocol packets
- `NinebotClient` class with `connect()`, `send()`, `receive()`, `request()`, `read_reg()`
- `Command` enum: READ=0x01, WRITE=0x02, WRITE_ACK_NO_REPLY=0x03, etc.
- `DeviceId` enum: ES_CONTROL=0x20, ES_BLE=0x21, ES_BATT=0x22

**Adding write support is straightforward:**
```python
async def write_reg(self, index, value):
    packet = Packet(
        DeviceId.PC, DeviceId.ES_BATT, Command.WRITE,
        register_offset, [value & 0xFF, (value >> 8) & 0xFF]
    )
    resp = await self.request(packet)
    return resp.data_index == 0  # 0 = success
```

### miauth (v0.9.7) - DEPENDENCY

- **PyPI:** `pip install miauth`
- **GitHub:** https://github.com/dnandha/miauth
- **Purpose:** NinebotCrypto encryption/decryption
- **Key class:** `miauth.nb.nbcrypto.NbCrypto`

### py9b - ALTERNATIVE

- **GitHub:** https://github.com/etransport/py9b
- **Features:** Firmware flashing, register read/write, multiple transport layers
- **Note:** Older codebase, may need adaptation for F-series crypto

---

## 15. F2 Pro Specific Notes

### Battery Configuration
- **Cells:** 10S (10 series groups) = registers 0x40-0x49
- **Nominal voltage:** 36V (3.6V per cell)
- **Capacity:** 12800 mAh (460 Wh)
- **Design voltage:** Check register 0x1A

### BLE Version
- F-series uses **BLE307** firmware variant
- Serial number prefix: **N5G** (F-series identification)
- The F2 Pro specifically uses NinebotCrypto (not Xiaomi Mi auth)

### BMS Firmware V1.3.4
- Version format: 0x0134 in register 0x17 (high nibble = PCB version, low 12 bits = firmware)
- BMS 1.3.4 is also used on Ninebot Max G30
- No specific known bugs documented for this version, but user reports charging/SOC issues after update

### Charging Behavior
- BMS requires periodic communication to enable/maintain charging
- Charging current protection limit: 1700mA
- Sending ANY valid packet periodically (e.g., read status) keeps charging active

---

## 16. Write Strategy for BMS Reset/Fix

### Diagnostic Read Phase

Read ALL these registers first to understand the current state:

```python
# Identity
BAT_SN          = 0x10  # 7 registers (14 bytes)
BAT_SW_VER      = 0x17  # Firmware version
BAT_CAPACITY    = 0x18  # Design capacity
BAT_TOTAL_CAP   = 0x19  # Actual/full charge capacity

# Status
BAT_FUN_BOOLEAN = 0x30  # Status flags (CRITICAL - check write lock bit)
BAT_REMAINING   = 0x31  # Current mAh
BAT_PERCENT     = 0x32  # SOC %
BAT_CURRENT     = 0x33  # Current draw
BAT_VOLTAGE     = 0x34  # Pack voltage
BAT_TEMP        = 0x35  # Temperature
BAT_BALANCE     = 0x36  # Cell balancing bitmap
BAT_ODIS_STATE  = 0x37  # Undervoltage flags
BAT_OCHG_STATE  = 0x38  # Overvoltage flags
BAT_CAP_COULO   = 0x39  # Coulomb counter
BAT_CAP_VOL     = 0x3A  # Voltage-based capacity
BAT_HEALTHY     = 0x3B  # Health %

# Cell voltages
BAT_CELL_1-10   = 0x40-0x49  # Individual cell mV

# Also read ESC error code
ESC_ERROR       = 0x1B  # On address 0x20
```

### Potential Write Targets

**WARNING: Writing to BMS registers can brick the battery. The scooter is already non-functional so the risk is accepted.**

1. **Check write lock (register 0x30, bit 4):**
   - Read 0x30 first
   - If bit 4 (BMS_BOOLMARK_WRITE_CMD) is 0, writes may be rejected
   - May need to set this bit first (write 0x30 with bit 4 set)

2. **ESC reboot (register 0x78 on address 0x20):**
   - Write value 1 to trigger system restart
   - May clear transient error states

3. **ESC power off (register 0x79 on address 0x20):**
   - Write value 1 for full shutdown

4. **Clear error state:**
   - Read ESC error register 0x1B
   - If error code present, a reboot (0x78) may clear it
   - Some errors only clear after hardware fix

5. **SOC recalibration attempt:**
   - Read BAT_REMAINING_CAP (0x31) and BAT_REMAINING_CAP_PERCENT (0x32)
   - Compare with BAT_TOTAL_CAPACITY (0x19)
   - If 0x19 is wrong, attempting to write the correct value (12800) might fix SOC
   - Read BAT_CAP_COULO (0x39) and BAT_CAP_VOL (0x3A) for coulomb/voltage estimator comparison

6. **Clear protection flags:**
   - Read BAT_OCHG_STATE (0x38) and BAT_ODIS_STATE (0x37)
   - If flags are set, BMS may be in protection mode preventing charge
   - Try writing 0x0000 to clear (may be rejected as read-only)

7. **MCU Reset (cmd=0x0A):**
   - Send CMD_MCU_RESET to BMS address (0x22)
   - This is a chip-level reset, no reply expected
   - Last resort before firmware reflash

### Firmware Reflash Option

If register writes fail, firmware reflash via BLE is supported:
1. CMD_IAP_BEGIN (0x07) with firmware size
2. CMD_IAP_TRANS (0x08) with firmware data blocks
3. CMD_IAP_VERIFY (0x09) with checksum
4. CMD_MCU_RESET (0x0A)

This requires having the correct BMS firmware binary file. Original firmware files may be available from https://firmware.scooterhacking.org or the scooterhacking/firmware GitHub repo.

---

## Sources

- [Official Ninebot ES Communication Protocol (nbdoc.pdf)](https://cloud.scooterhacking.org/release/nbdoc.pdf)
- [etransport/ninebot-docs Wiki - Protocol](https://github.com/etransport/ninebot-docs/wiki/protocol)
- [etransport/ninebot-docs Wiki - M365BMS](https://github.com/etransport/ninebot-docs/wiki/M365BMS)
- [CamiAlfa/M365-BLE-PROTOCOL - Register Map](https://github.com/CamiAlfa/M365-BLE-PROTOCOL/blob/master/m365_register_map.h)
- [scooterhacking/NinebotCrypto](https://github.com/scooterhacking/NinebotCrypto)
- [dnandha/miauth](https://github.com/dnandha/miauth)
- [ownbee/ninebot-ble](https://github.com/ownbee/ninebot-ble)
- [etransport/py9b](https://github.com/etransport/py9b)
- [E-Scooter Bluetooth LE insides (irmos techblog)](https://www.irmo.de/2023/11/08/e-scooter-bluetooth-hacking/)
- [ScooterHacking.org Wiki - Error Codes](https://wiki.scooterhacking.org/doku.php?id=nberrorcodes)
- [ScooterHacking.org - BMS Custom Firmware Toolkit](https://bms.scooterhacking.org/)
- [Ninebot IAP Flashing Tool](https://iap.scooterhacking.org/)
- [Joey Babcock Wiki - Ninebot BMS Documentation](https://joeybabcock.me/wiki/Ninebot_ESX_BMS_1.6.0)
- [py9b Issue #4 - External BMS Communication](https://github.com/etransport/py9b/issues/4)
