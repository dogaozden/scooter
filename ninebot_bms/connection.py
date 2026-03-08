"""
BLE connection manager for Ninebot F2 Pro scooters.

Handles BLE transport (connect, notify, fragment), NinebotCrypto
authentication via the miauth library, and a request/response API
for reading and writing Ninebot protocol registers.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from typing import Any

from bleak import BleakClient, BleakGATTCharacteristic

from miauth.nb.nbcrypto import NbCrypto
from miauth.nb.nbcommand import NbCommand

from ninebot_bms.protocol import (
    CMD_READ,
    CMD_READ_RESP,
    CMD_WRITE_RESP,
    build_packet,
    build_read_cmd,
    build_write_cmd,
    build_write_bytes_cmd,
    extract_packet,
    format_packet_hex,
    parse_packet,
    ADDR_APP,
    ADDR_BLE,
    ADDR_BMS,
)
from ninebot_bms.scanner import (
    NUS_SERVICE_UUID,
    NUS_RX_UUID,
    NUS_TX_UUID,
    LEGACY_SERVICE_UUID,
    LEGACY_CHAR_UUID,
)

logger = logging.getLogger(__name__)


class NinebotConnection:
    """Manages a BLE connection to a Ninebot scooter.

    Handles service discovery, NinebotCrypto authentication, encrypted
    packet send/receive with 20-byte BLE fragmentation, and convenient
    register read/write helpers.
    """

    BLE_CHUNK_SIZE = 20

    def __init__(self) -> None:
        self._client: BleakClient | None = None
        self._rx_uuid: str = NUS_RX_UUID   # write TO scooter
        self._tx_uuid: str = NUS_TX_UUID   # notify FROM scooter
        self._buf: bytearray = bytearray()
        self._response_future: asyncio.Future | None = None
        self._crypto: NbCrypto | None = None
        self._authenticated: bool = False
        self._device_name: bytes = b""
        self._ble_key: bytes = b""
        self._serial: bytes = b""
        self._loop: asyncio.AbstractEventLoop | None = None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_connected(self) -> bool:
        """True if the BLE client is connected."""
        return self._client is not None and self._client.is_connected

    @property
    def is_authenticated(self) -> bool:
        """True if the NinebotCrypto authentication handshake completed."""
        return self._authenticated

    # ------------------------------------------------------------------
    # Connect / Disconnect
    # ------------------------------------------------------------------

    async def connect(
        self, address: str, device_name: str | None = None, timeout: float = 30.0
    ) -> bool:
        """Connect to a Ninebot scooter at *address*.

        *device_name* should be the advertised BLE name from the scan
        (e.g. ``"NAGSF2430C0153"``).  It is used by the NinebotCrypto
        key derivation — an incorrect name makes authentication fail.

        Discovers GATT services and subscribes to notifications on the
        appropriate TX characteristic (NUS preferred, legacy FFE0/FFE1
        as fallback).

        Returns True on success.
        """
        self._loop = asyncio.get_running_loop()
        # Clean up any previous connection first
        if self._client is not None:
            try:
                await self._client.stop_notify(self._tx_uuid)
            except Exception:
                pass
            try:
                await self._client.disconnect()
            except Exception:
                pass
            self._client = None
            await asyncio.sleep(0.5)  # Let CoreBluetooth clean up

        # Reset all state from any previous connection
        self._authenticated = False
        self._crypto = None
        self._buf.clear()
        self._response_future = None
        self._client = BleakClient(address, timeout=timeout)

        try:
            await self._client.connect()
        except Exception as exc:
            logger.error("BLE connect failed: %s", exc)
            self._client = None
            return False

        if not self._client.is_connected:
            logger.error("BLE client reports not connected after connect()")
            self._client = None
            return False

        # Discover services and pick the right characteristics
        if not self._resolve_characteristics():
            logger.error(
                "Could not find NUS or legacy UART service on device"
            )
            await self._client.disconnect()
            self._client = None
            return False

        # Subscribe to notifications on the TX characteristic
        try:
            await self._client.start_notify(self._tx_uuid, self._on_notify)
            # Give macOS CoreBluetooth time to finish the CCCD write
            await asyncio.sleep(0.5)
            logger.debug("Notification subscription active on %s", self._tx_uuid)
        except Exception as exc:
            logger.error("Failed to subscribe to notifications: %s", exc)
            await self._client.disconnect()
            self._client = None
            return False

        # Device name for NinebotCrypto key derivation.
        # MUST come from the BLE scan advertisement, not from GAP.
        if device_name:
            self._device_name = device_name.encode("utf-8")
        else:
            # Fallback: try GAP, then address-based
            try:
                name_bytes = await self._client.read_gatt_char(
                    "00002a00-0000-1000-8000-00805f9b34fb"
                )
                self._device_name = bytes(name_bytes)
            except Exception:
                self._device_name = address.replace(":", "").encode()[:16]
                logger.warning(
                    "No device name provided and GAP read failed; "
                    "using fallback: %r (auth will likely fail)",
                    self._device_name,
                )

        print(f"Connected to {address}")
        return True

    def _resolve_characteristics(self) -> bool:
        """Pick RX/TX characteristic UUIDs from discovered services.

        Prefers the Nordic UART Service; falls back to the legacy
        FFE0/FFE1 pair if NUS is not present.

        Returns True if a suitable pair was found.
        """
        assert self._client is not None

        services = self._client.services
        nus_lower = NUS_SERVICE_UUID.lower()
        legacy_lower = LEGACY_SERVICE_UUID.lower()

        for service in services:
            if service.uuid.lower() == nus_lower:
                self._rx_uuid = NUS_RX_UUID
                self._tx_uuid = NUS_TX_UUID
                logger.info("Using NUS service")
                return True

        # Fallback: legacy FFE0 service
        for service in services:
            if service.uuid.lower() == legacy_lower:
                self._rx_uuid = LEGACY_CHAR_UUID
                self._tx_uuid = LEGACY_CHAR_UUID
                logger.info("Using legacy FFE0/FFE1 service")
                return True

        return False

    async def disconnect(self) -> None:
        """Stop notifications and disconnect the BLE client."""
        if self._client is not None:
            try:
                await self._client.stop_notify(self._tx_uuid)
            except Exception:
                pass
            try:
                await self._client.disconnect()
            except Exception:
                pass
            self._client = None
        self._authenticated = False
        self._crypto = None
        self._buf.clear()
        self._response_future = None
        print("Disconnected.")

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    async def authenticate(self) -> bool:
        """Run the NinebotCrypto authentication handshake.

        The flow mirrors the miauth NbClient auth sequence:
          1. Send CMD_INIT, receive BLE key + serial.
          2. Send CMD_PING with a random app key.
          3. If not yet paired, prompt the user to press the power button
             and send CMD_PAIR.
          4. Derive the final shared key.

        If the crypto handshake fails or times out, the method attempts a
        fallback to raw unencrypted communication.

        Returns True on success.
        """
        if not self.is_connected:
            logger.error("Cannot authenticate: not connected")
            return False

        # Reset state from any previous session so _on_notify uses
        # the auth branch, not the post-auth branch.
        self._authenticated = False
        self._buf.clear()
        self._response_future = None

        app_key = secrets.token_bytes(16)

        # ---------------------------------------------------------------
        # Stage 1: INIT (with retries — macOS BLE can be slow)
        # ---------------------------------------------------------------
        print("Authenticating...")

        init_response = None
        for init_attempt in range(3):
            # Re-create crypto for each attempt (encrypt mutates state)
            self._crypto = NbCrypto()
            self._crypto.set_name(self._device_name)
            init_cmd = NbCommand.CMD_INIT  # 5AA5 00 3D21 5B 00
            init_encrypted = self._crypto.encrypt(init_cmd)

            init_response = await self._auth_send_and_wait(
                init_encrypted, timeout=5.0
            )
            if init_response is not None:
                break
            logger.warning(
                "INIT attempt %d/3 timed out, retrying...", init_attempt + 1
            )
            await asyncio.sleep(1.0)

        if init_response is None:
            print("No response to INIT — trying unencrypted fallback...")
            return await self._try_unencrypted_fallback()

        # Decrypt the INIT response
        try:
            init_dec = self._crypto.decrypt(init_response)
        except Exception as exc:
            logger.error("Failed to decrypt INIT response: %s", exc)
            return await self._try_unencrypted_fallback()

        # Validate: ACK_INIT header is 7 bytes, payload starts after that
        ack_len = NbCommand.ACK_LEN  # 7
        if len(init_dec) < ack_len + 16:
            logger.error("INIT response too short: %d bytes", len(init_dec))
            return await self._try_unencrypted_fallback()

        cmd_header = init_dec[:ack_len]
        payload = init_dec[ack_len:]

        if cmd_header != NbCommand.ACK_INIT:
            logger.error("Unexpected INIT response cmd: %s", cmd_header.hex())
            return await self._try_unencrypted_fallback()

        self._ble_key = payload[:16]
        self._serial = payload[16:]
        logger.info("BLE key: %s", self._ble_key.hex())
        logger.info("Serial: %s", self._serial)

        # Update crypto with BLE key (stage 2 key derivation)
        self._crypto.set_ble_data(self._ble_key)

        # ---------------------------------------------------------------
        # Stage 2: PING
        # ---------------------------------------------------------------
        # The scooter needs a moment between INIT and PING
        await asyncio.sleep(0.5)

        ping_response = None
        for ping_attempt in range(3):
            ping_cmd = NbCommand.CMD_PING(app_key)
            ping_encrypted = self._crypto.encrypt(ping_cmd)
            ping_response = await self._auth_send_and_wait(
                ping_encrypted, timeout=5.0
            )
            if ping_response is not None:
                break
            logger.warning(
                "PING attempt %d/3 timed out, retrying...", ping_attempt + 1
            )
            await asyncio.sleep(1.0)

        if ping_response is None:
            logger.error("No response to PING after 3 attempts")
            return await self._try_unencrypted_fallback()

        try:
            ping_dec = self._crypto.decrypt(ping_response)
        except Exception as exc:
            logger.error("Failed to decrypt PING response: %s", exc)
            return await self._try_unencrypted_fallback()

        ping_header = ping_dec[:ack_len]

        # ACK_PRE (reg==0) means not paired yet, ACK_PING (reg==1) means paired
        if ping_header == NbCommand.ACK_PRE:
            # ---------------------------------------------------------------
            # Stage 3: PAIR (device not previously paired)
            # ---------------------------------------------------------------
            # Matches miauth NbClient state machine:
            #   PRE:  send CMD_PAIR → receive ACK_PING → set_app_data
            #   PAIR: send CMD_PAIR → receive ACK_PAIR → COMM
            print(">> Press the POWER BUTTON on your scooter now!")
            print("   Waiting for pairing confirmation...")

            got_ping_ack = False
            for attempt in range(15):  # wait up to ~30s
                pair_cmd = NbCommand.CMD_PAIR(self._serial)
                pair_encrypted = self._crypto.encrypt(pair_cmd)

                pair_response = await self._auth_send_and_wait(
                    pair_encrypted, timeout=3.0
                )
                if pair_response is not None:
                    try:
                        pair_dec = self._crypto.decrypt(pair_response)
                        pair_header = pair_dec[:ack_len]
                        if pair_header == NbCommand.ACK_PING:
                            # Button was pressed! Derive the final key.
                            self._crypto.set_app_data(app_key)
                            got_ping_ack = True
                            break
                        elif pair_header == NbCommand.ACK_PAIR:
                            # Direct pair acknowledgement
                            got_ping_ack = True
                            self._crypto.set_app_data(app_key)
                            break
                    except Exception:
                        pass

                await asyncio.sleep(2.0)

            if not got_ping_ack:
                logger.error("Pairing timed out")
                return False

            # Send final PAIR (encrypted with the final key) to complete
            # the handshake, matching NbClient's PAIR state.
            final_pair_cmd = NbCommand.CMD_PAIR(self._serial)
            final_pair_enc = self._crypto.encrypt(final_pair_cmd)
            final_resp = await self._auth_send_and_wait(
                final_pair_enc, timeout=5.0
            )
            if final_resp is not None:
                try:
                    final_dec = self._crypto.decrypt(final_resp)
                    final_header = final_dec[:ack_len]
                    if final_header == NbCommand.ACK_PAIR:
                        logger.info("Final PAIR acknowledged")
                    else:
                        logger.warning(
                            "Unexpected final PAIR response: %s",
                            final_header.hex(),
                        )
                except Exception as exc:
                    logger.warning("Could not decrypt final PAIR response: %s", exc)
            else:
                logger.warning("No response to final PAIR (continuing anyway)")

        elif ping_header == NbCommand.ACK_PING:
            # Already paired -- derive final key
            self._crypto.set_app_data(app_key)

            # Send final PAIR to complete handshake
            final_pair_cmd = NbCommand.CMD_PAIR(self._serial)
            final_pair_enc = self._crypto.encrypt(final_pair_cmd)
            final_resp = await self._auth_send_and_wait(
                final_pair_enc, timeout=5.0
            )
            if final_resp is not None:
                try:
                    final_dec = self._crypto.decrypt(final_resp)
                    logger.info("Final PAIR response: %s", final_dec[:ack_len].hex())
                except Exception:
                    pass
        else:
            logger.error("Unexpected PING response: %s", ping_header.hex())
            return await self._try_unencrypted_fallback()

        # ---------------------------------------------------------------
        # Finalize
        # ---------------------------------------------------------------
        self._authenticated = True
        self._buf.clear()  # Clear any stale data from auth phase
        print("Authentication successful!")
        return True

    async def _try_unencrypted_fallback(self) -> bool:
        """Attempt raw unencrypted communication as a fallback.

        Some older scooters (or scooters in a certain mode) respond to
        Ninebot protocol packets without the NinebotCrypto wrapper.

        Sends a simple read command and checks for a valid response.
        Returns True if the scooter responds without encryption.
        """
        print("Trying unencrypted communication...")
        self._crypto = None
        self._authenticated = False

        # Try reading a basic register (e.g. BMS serial number at reg 0x10)
        test_packet = build_read_cmd(ADDR_BMS, 0x10, 2)

        try:
            self._buf.clear()
            self._response_future = self._loop.create_future()

            await self.send_raw(test_packet)
            raw_response = await asyncio.wait_for(
                self._response_future, timeout=3.0
            )
        except (asyncio.TimeoutError, Exception):
            raw_response = None
        finally:
            self._response_future = None

        if raw_response is not None:
            parsed = parse_packet(raw_response)
            if parsed is not None and parsed.get("valid"):
                print("Unencrypted communication works — skipping auth.")
                self._authenticated = False  # no crypto, but we can talk
                return True

        print("Unencrypted fallback failed. Cannot communicate with scooter.")
        return False

    async def _auth_send_and_wait(
        self, data: bytes, timeout: float = 5.0
    ) -> bytes | None:
        """Send raw bytes and wait for a complete NbCrypto-framed response.

        During authentication the crypto layer uses the 5AA5 header for
        framing. A complete message is identified when the accumulated
        buffer length matches ``buf[2] + 7`` (the miauth framing rule).

        Returns the raw (still encrypted) response bytes, or None on timeout.
        """
        self._buf.clear()
        auth_future: asyncio.Future[bytes] = self._loop.create_future()
        self._response_future = auth_future

        logger.debug("_auth_send_and_wait: sending %s (%d bytes), timeout=%.1f",
                     data.hex(), len(data), timeout)
        await self.send_raw(data)
        logger.debug("_auth_send_and_wait: send_raw done, waiting for response...")

        try:
            result = await asyncio.wait_for(auth_future, timeout=timeout)
            logger.debug("_auth_send_and_wait: got response %s (%d bytes)",
                         result.hex(), len(result))
            return result
        except asyncio.TimeoutError:
            logger.debug("_auth_send_and_wait: TIMEOUT after %.1fs (buf=%s, %d bytes)",
                         timeout, self._buf.hex(), len(self._buf))
            return None
        finally:
            self._response_future = None

    # ------------------------------------------------------------------
    # Notification handler
    # ------------------------------------------------------------------

    def _on_notify(
        self,
        sender: BleakGATTCharacteristic | Any,
        data: bytearray,
    ) -> None:
        """BLE notification callback.

        Accumulates incoming BLE fragments in ``self._buf``. During the
        auth phase the miauth framing rule is used (length byte at
        offset 2 determines message completeness). After authentication
        the Ninebot protocol ``extract_packet`` function is used.
        """
        incoming = bytes(data)
        logger.debug(
            "_on_notify TOP: incoming=%s (%d bytes) auth=%s crypto=%s future=%s",
            incoming.hex(), len(incoming),
            self._authenticated,
            self._crypto is not None,
            self._response_future is not None and not self._response_future.done()
            if self._response_future else None,
        )

        if self._authenticated and self._crypto is not None:
            # Post-auth: incoming data is encrypted.
            # Fragments start with 5AA5 header for the first chunk.
            if incoming[:2] == b"\x5a\xa5":
                self._buf = bytearray(incoming)
            else:
                self._buf.extend(incoming)
            logger.debug("_on_notify post-auth: incoming=%s buf=%s (%d bytes)",
                         incoming.hex(), self._buf.hex(), len(self._buf))

            # Follow the ninebot-ble library approach: decrypt on every
            # fragment and check if len(decrypted) == buf[2] + 7.
            # NbCrypto.decrypt() handles partial data gracefully.
            if len(self._buf) >= 3:
                try:
                    decrypted = self._crypto.decrypt(self._buf)
                    expected_len = self._buf[2] + 7
                    logger.debug("_on_notify: decrypted=%s (%d bytes), expected=%d",
                                 decrypted.hex(), len(decrypted), expected_len)
                    if len(decrypted) == expected_len:
                        # Decrypted packet has no CRC — append one so the
                        # rest of our codebase (parse_packet etc.) works.
                        from ninebot_bms.protocol import calc_checksum
                        crc = calc_checksum(decrypted[2:])
                        full_packet = bytes(decrypted) + crc
                        logger.debug("_on_notify: COMPLETE packet=%s", full_packet.hex())
                        if self._response_future and not self._response_future.done():
                            self._response_future.set_result(full_packet)
                        self._buf.clear()
                    else:
                        logger.debug("_on_notify: incomplete, waiting for more fragments")
                except Exception as exc:
                    # Partial data or decrypt error — wait for more fragments
                    logger.debug("_on_notify: decrypt error (partial data?): %s", exc)
        elif not self._authenticated and self._crypto is not None:
            # During auth: accumulate and check miauth framing
            logger.debug("_on_notify AUTH branch: incoming=%s (%d bytes)",
                         incoming.hex(), len(incoming))
            if incoming[:2] == b"\x5a\xa5":
                self._buf = bytearray(incoming)
                logger.debug("_on_notify AUTH: new message start, buf reset")
            else:
                self._buf.extend(incoming)
                logger.debug("_on_notify AUTH: appended, buf now %d bytes", len(self._buf))

            # miauth completeness check: total = buf[2] + 7
            # (from NbClient.main_handler: len(dec) == receive_buffer[2] + 7)
            # But buf[2] is the encrypted length field. The encrypted message
            # is complete when we have buf[2] + 13 bytes (3 header + 4 base + payload + 4 MAC + 2 iter).
            if len(self._buf) >= 3:
                expected_len = self._buf[2] + 13
                logger.debug("_on_notify AUTH: buf=%s (%d bytes), buf[2]=0x%02X, expected_len=%d",
                             self._buf.hex(), len(self._buf), self._buf[2], expected_len)
                if len(self._buf) >= expected_len:
                    logger.debug("_on_notify AUTH: COMPLETE! resolving future (future=%s)",
                                 self._response_future is not None and not self._response_future.done()
                                 if self._response_future else None)
                    if self._response_future and not self._response_future.done():
                        self._response_future.set_result(bytes(self._buf))
                    self._buf.clear()
                else:
                    logger.debug("_on_notify AUTH: incomplete, need %d more bytes",
                                 expected_len - len(self._buf))
        else:
            # No crypto at all (unencrypted fallback mode)
            if incoming[:2] == b"\x5a\xa5":
                self._buf = bytearray(incoming)
            else:
                self._buf.extend(incoming)

            # Use the Ninebot protocol framing
            packet, remaining = extract_packet(self._buf)
            if packet is not None:
                self._buf = remaining
                if self._response_future and not self._response_future.done():
                    self._response_future.set_result(packet)

    # ------------------------------------------------------------------
    # Send primitives
    # ------------------------------------------------------------------

    async def send_raw(self, data: bytes) -> None:
        """Fragment *data* into BLE_CHUNK_SIZE chunks and write to scooter.

        Each chunk is written to the RX characteristic with
        ``response=False``. A 20 ms delay is inserted between chunks
        when fragmentation is needed.
        """
        if self._client is None or not self._client.is_connected:
            raise RuntimeError("Not connected")

        offset = 0
        total = len(data)
        while offset < total:
            end = min(offset + self.BLE_CHUNK_SIZE, total)
            chunk = data[offset:end]
            await self._client.write_gatt_char(
                self._rx_uuid, chunk, response=False
            )
            offset = end
            if offset < total:
                await asyncio.sleep(0.02)  # 20 ms inter-chunk delay

    async def send_packet(self, packet: bytes) -> None:
        """Send a Ninebot protocol packet, encrypting if authenticated.

        When authenticated, the Ninebot CRC (last 2 bytes) is stripped
        before passing through ``NbCrypto.encrypt()``, because the crypto
        layer uses its own MAC for integrity (matching the ninebot-ble
        library's ``Packet.pack()`` which never includes CRC).
        """
        if self._authenticated and self._crypto is not None:
            # Strip the trailing 2-byte Ninebot CRC — NbCrypto doesn't use it
            packet_no_crc = packet[:-2]
            logger.debug("send_packet: raw=%s  no_crc=%s", packet.hex(), packet_no_crc.hex())
            encrypted = self._crypto.encrypt(packet_no_crc)
            logger.debug("send_packet: encrypted=%s (%d bytes)", encrypted.hex(), len(encrypted))
            await self.send_raw(encrypted)
        else:
            await self.send_raw(packet)

    # ------------------------------------------------------------------
    # Request / Response
    # ------------------------------------------------------------------

    async def request(
        self,
        packet: bytes,
        timeout: float = 5.0,
        retries: int = 3,
    ) -> dict[str, Any] | None:
        """Send a packet and wait for a matching response.

        Uses an ``asyncio.Future`` to bridge the notification callback.
        Retries with linear backoff (0.5 s, 1.0 s, 1.5 s, ...) on
        timeout.

        Returns the parsed response dict, or None if all retries fail.
        """
        if self._loop is None:
            self._loop = asyncio.get_running_loop()

        # Parse the outgoing packet to know what response to expect
        sent = parse_packet(packet)

        for attempt in range(1, retries + 1):
            self._buf.clear()
            future: asyncio.Future[bytes] = self._loop.create_future()
            self._response_future = future

            try:
                await self.send_packet(packet)
                raw_response = await asyncio.wait_for(future, timeout=timeout)
            except asyncio.TimeoutError:
                backoff = 0.5 * attempt
                logger.warning(
                    "Request timeout (attempt %d/%d), retrying in %.1fs...",
                    attempt,
                    retries,
                    backoff,
                )
                self._response_future = None
                await asyncio.sleep(backoff)
                continue
            except Exception as exc:
                logger.error("Request error: %s", exc)
                self._response_future = None
                return None
            finally:
                self._response_future = None

            # Parse the response
            parsed = parse_packet(raw_response)
            if parsed is None:
                logger.warning("Could not parse response: %s", raw_response.hex())
                continue

            if not parsed.get("valid"):
                logger.warning(
                    "Response checksum invalid: %s",
                    format_packet_hex(raw_response),
                )
                continue

            # Validate that it is a response to our command
            if sent is not None:
                expected_cmd = (
                    CMD_READ_RESP
                    if sent["cmd"] == CMD_READ
                    else CMD_WRITE_RESP
                )
                if parsed["cmd"] != expected_cmd:
                    logger.warning(
                        "Unexpected response cmd 0x%02X (expected 0x%02X)",
                        parsed["cmd"],
                        expected_cmd,
                    )
                    # Still return it — the caller can decide
                if parsed["reg"] != sent["reg"]:
                    logger.warning(
                        "Response reg 0x%02X does not match request reg 0x%02X",
                        parsed["reg"],
                        sent["reg"],
                    )

            return parsed

        logger.error("Request failed after %d retries", retries)
        return None

    # ------------------------------------------------------------------
    # Convenience: register read / write
    # ------------------------------------------------------------------

    async def read_reg(
        self, dst: int, reg: int, length: int
    ) -> bytes | None:
        """Read *length* bytes starting at register *reg* on device *dst*.

        Returns the raw data bytes from the response, or None on failure.
        """
        packet = build_read_cmd(dst, reg, length)
        resp = await self.request(packet)
        if resp is None:
            return None
        return resp.get("data", b"") or None

    async def write_reg(
        self,
        dst: int,
        reg: int,
        value: int,
        with_reply: bool = True,
    ) -> tuple[bool, str]:
        """Write a 16-bit *value* to register *reg* on device *dst*.

        Returns (success, message).
        """
        packet = build_write_cmd(dst, reg, value, with_reply=with_reply)

        if not with_reply:
            await self.send_packet(packet)
            return True, "Sent (no reply requested)"

        resp = await self.request(packet)
        if resp is None:
            return False, "No response"

        # Parse write-response status
        data: bytes = resp.get("data", b"")
        if not data:
            return False, "Empty write response"

        from ninebot_bms.protocol import parse_write_response

        return parse_write_response(resp)

    async def write_reg_bytes(
        self,
        dst: int,
        reg: int,
        data: bytes,
        with_reply: bool = True,
    ) -> tuple[bool, str]:
        """Write arbitrary *data* bytes to register *reg* on device *dst*.

        Returns (success, message).
        """
        packet = build_write_bytes_cmd(dst, reg, data, with_reply=with_reply)

        if not with_reply:
            await self.send_packet(packet)
            return True, "Sent (no reply requested)"

        resp = await self.request(packet)
        if resp is None:
            return False, "No response"

        from ninebot_bms.protocol import parse_write_response

        return parse_write_response(resp)
