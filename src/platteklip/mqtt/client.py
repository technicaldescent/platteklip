# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""MQTT v5 client (stdlib-only, IPv6-only, minimal surface).

A producer-oriented MQTT v5 client with a Paho-like
lifecycle (``connect_async`` + ``loop_start``).  The
client runs a selector-based I/O thread and exposes
callback hooks for connect, disconnect, publish, and
logging events.

Design constraints
------------------
Protocol
    MQTT v5 only.  The v5 protocol level byte (5) is
    sent in every CONNECT packet.
Transport
    TCP only.  No WebSocket or Unix socket support.
Network
    IPv6 only (``AF_INET6`` with ``IPV6_V6ONLY=1``).
    Dual-stack or IPv4 fallback is explicitly rejected.
TLS
    TLS enforcement is the caller's responsibility via
    an ``ssl.SSLContext`` passed to
    :meth:`Client.tls_set_context`.
QoS
    Publish supports QoS 1 and QoS 2 only.  QoS 0 is
    rejected to guarantee at-least-once delivery.

Reference
---------
MQTT v5.0 specification:
    https://docs.oasis-open.org/mqtt/mqtt/v5.0/
"""

import collections
import contextlib
import logging
import selectors
import socket
import ssl
import struct
import threading
import time
from dataclasses import dataclass
from typing import Any, Final

from .enums import (
    CallbackAPIVersion,
    MQTTErrorCode,
    MQTTProtocolVersion,
)
from .packettypes import PacketTypes
from .properties import (
    Properties,
    _decode_varint,
    _encode_varint,
)
from .reasoncodes import ReasonCode

# ----------------------------------------------------------------
# Public re-exports for compatibility with the producer module.
# These allow ``import platteklip.mqtt.client as mqtt`` followed
# by ``mqtt.MQTTv5``, ``mqtt.MQTT_ERR_SUCCESS``, etc.
# ----------------------------------------------------------------
MQTTv5: Final[MQTTProtocolVersion] = MQTTProtocolVersion.MQTTv5
MQTT_ERR_SUCCESS: Final[MQTTErrorCode] = MQTTErrorCode.MQTT_ERR_SUCCESS
MQTT_ERR_INVAL: Final[MQTTErrorCode] = MQTTErrorCode.MQTT_ERR_INVAL
MQTT_ERR_NO_CONN: Final[MQTTErrorCode] = MQTTErrorCode.MQTT_ERR_NO_CONN
MQTT_ERR_CONN_LOST: Final[MQTTErrorCode] = MQTTErrorCode.MQTT_ERR_CONN_LOST
MQTT_ERR_QUEUE_SIZE: Final[MQTTErrorCode] = MQTTErrorCode.MQTT_ERR_QUEUE_SIZE
MQTT_ERR_PROTOCOL: Final[MQTTErrorCode] = MQTTErrorCode.MQTT_ERR_PROTOCOL
MQTT_ERR_UNKNOWN: Final[MQTTErrorCode] = MQTTErrorCode.MQTT_ERR_UNKNOWN

_ALLOWED_QOS: Final[frozenset[int]] = frozenset({1, 2})
_LOG: Final[logging.Logger] = logging.getLogger(__name__)

_FIXED_FLAGS: Final[dict[PacketTypes, int]] = {
    PacketTypes.PUBREL: 0x02,
    PacketTypes.SUBSCRIBE: 0x02,
    PacketTypes.UNSUBSCRIBE: 0x02,
}


# ----------------------------------------------------------------
# Supporting dataclasses
# ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ConnectFlags:
    """Flags from a CONNACK packet.

    Parameters
    ----------
    session_present
        ``True`` if the broker has a stored session
        for this client ID.
    """

    session_present: bool


@dataclass(frozen=True, slots=True)
class DisconnectFlags:
    """Flags accompanying a disconnect event.

    Parameters
    ----------
    is_disconnect_packet_from_server
        ``True`` if the broker sent a DISCONNECT
        packet; ``False`` if the client initiated
        the disconnection.
    """

    is_disconnect_packet_from_server: bool


class MQTTMessageInfo:
    """Result handle for a publish operation.

    Attributes
    ----------
    mid
        The message identifier assigned by the client.
    rc
        The result code.  Set to
        :data:`MQTT_ERR_SUCCESS` on success or an
        appropriate error code on failure.
    """

    __slots__ = ("mid", "rc")

    def __init__(self, mid: int) -> None:
        """Initialise with a message identifier."""
        self.mid: int = mid
        self.rc: MQTTErrorCode = MQTT_ERR_SUCCESS


@dataclass(slots=True)
class _QueuedPacket:
    """An outbound packet waiting to be sent.

    Attributes
    ----------
    packet_type
        The MQTT control packet type.
    data
        The fully encoded packet bytes.
    pos
        The current send position within *data*.
    mid
        The message identifier (0 for non-publish).
    qos
        The QoS level (0 for non-publish).
    """

    packet_type: PacketTypes
    data: bytes
    pos: int
    mid: int
    qos: int


# ----------------------------------------------------------------
# Client
# ----------------------------------------------------------------


class Client:
    """MQTT v5 client with a selector-based I/O thread.

    The client follows a Paho-like lifecycle:

    1. Create an instance and configure TLS.
    2. Call :meth:`connect_async` to set connection
       parameters.
    3. Call :meth:`loop_start` to spawn the I/O thread.
    4. Call :meth:`publish` to send messages.
    5. Call :meth:`disconnect` and :meth:`loop_stop`
       to shut down.

    Parameters
    ----------
    callback_api_version
        Must be ``CallbackAPIVersion.VERSION2``.
    client_id
        The MQTT client identifier.  May be empty for
        broker-assigned identifiers.
    userdata
        Arbitrary data passed to every callback.
    protocol
        Must be ``MQTTProtocolVersion.MQTTv5``.
    transport
        Must be ``"tcp"``.
    reconnect_on_failure
        If ``True``, the I/O thread will reconnect
        automatically after connection loss.
    manual_ack
        Reserved for future use.
    """

    def __init__(
        self,
        *,
        callback_api_version: CallbackAPIVersion = (CallbackAPIVersion.VERSION2),
        client_id: str | None = None,
        userdata: Any = None,
        protocol: MQTTProtocolVersion = MQTTv5,
        transport: str = "tcp",
        reconnect_on_failure: bool = True,
        manual_ack: bool = False,
    ) -> None:
        """Initialise the client and validate parameters."""
        if callback_api_version is not (CallbackAPIVersion.VERSION2):
            raise ValueError(
                "Only callback API version 2 " "is supported",
            )
        if protocol is not MQTTv5:
            raise ValueError(
                "Only MQTT v5 is supported",
            )
        if transport.lower() != "tcp":
            raise ValueError(
                "Only TCP transport is supported",
            )

        self._protocol: MQTTProtocolVersion = protocol
        self._userdata: Any = userdata
        self._client_id: bytes = (client_id or "").encode("utf-8")
        self._reconnect_on_failure: bool = bool(
            reconnect_on_failure,
        )
        self._manual_ack: bool = bool(manual_ack)

        # Connection parameters (set by connect_async)
        self._host: str = ""
        self._port: int = 1883
        self._keepalive: int = 60
        self._connect_timeout: float = 5.0
        self._bind_address: str = ""
        self._bind_port: int = 0

        # TLS
        self._ssl_context: ssl.SSLContext | None = None
        self._ssl_enabled: bool = False

        # Authentication (reserved for future use)
        self._username: bytes | None = None
        self._password: bytes | None = None

        # Flow control
        self._max_inflight_messages: int = 20
        self._max_queued_messages: int = 0  # 0 = unlimited
        self._reconnect_min_delay: int = 1
        self._reconnect_max_delay: int = 120
        self._reconnect_delay: int | None = None

        # Async connect state
        self._connect_properties: Properties | None = None
        self._clean_start: bool = True

        # Socket + selector thread
        self._sock: socket.socket | ssl.SSLSocket | None = None
        self._selector: selectors.BaseSelector | None = None
        self._thread: threading.Thread | None = None
        self._thread_stop: threading.Event = threading.Event()

        # Wakeup pipe (AF_UNIX socketpair)
        self._wakeup_r: socket.socket | None = None
        self._wakeup_w: socket.socket | None = None

        # Outbound packet queue
        self._outq: collections.deque[_QueuedPacket] = collections.deque()
        self._out_lock: threading.Lock = threading.Lock()
        self._mid_lock: threading.Lock = threading.Lock()
        self._last_mid: int = 0

        # QoS in-flight tracking: mid → qos (1 or 2)
        self._inflight: dict[int, int] = {}

        # Keepalive timestamps
        self._last_in: float = time.monotonic()
        self._last_out: float = time.monotonic()
        self._awaiting_pingresp: bool = False

        # Callbacks (set by the caller)
        self.on_connect: Any = None
        self.on_disconnect: Any = None
        self.on_publish: Any = None
        self.on_log: Any = None
        self._logger: logging.Logger | None = None

        # Connection state
        self._connected: bool = False
        self._connecting: bool = False

    # ============================================================
    # Public tuning API
    # ============================================================

    def enable_logger(
        self,
        logger: logging.Logger | None = None,
    ) -> None:
        """Attach a Python logger to the client.

        Parameters
        ----------
        logger
            The logger instance.  If ``None``, a
            module-level logger is used.
        """
        self._logger = logger or logging.getLogger(
            __name__,
        )

    def max_inflight_messages_set(
        self,
        inflight: int,
    ) -> None:
        """Set the maximum number of in-flight QoS > 0 messages.

        Parameters
        ----------
        inflight
            Maximum concurrent unacknowledged messages.
            Must be >= 0.
        """
        if inflight < 0:
            raise ValueError(
                "max_inflight_messages must be >= 0",
            )
        self._max_inflight_messages = inflight

    def max_queued_messages_set(
        self,
        queue_size: int,
    ) -> Client:
        """Set the maximum outbound queue depth.

        Parameters
        ----------
        queue_size
            Maximum queued messages.  0 means unlimited.
            Must be >= 0.

        Returns
        -------
        Client
            Self, for method chaining.
        """
        if queue_size < 0:
            raise ValueError(
                "max_queued_messages must be >= 0",
            )
        self._max_queued_messages = queue_size
        return self

    def reconnect_delay_set(
        self,
        *,
        min_delay: int = 1,
        max_delay: int = 120,
    ) -> None:
        """Configure exponential backoff for reconnection.

        Parameters
        ----------
        min_delay
            Initial delay in seconds.
        max_delay
            Maximum delay in seconds.
        """
        if min_delay < 0 or max_delay < 0 or max_delay < min_delay:
            raise ValueError(
                "Invalid reconnect delay bounds",
            )
        self._reconnect_min_delay = min_delay
        self._reconnect_max_delay = max_delay
        self._reconnect_delay = None

    def tls_set_context(
        self,
        context: ssl.SSLContext | None = None,
    ) -> None:
        """Configure TLS using an existing SSLContext.

        Parameters
        ----------
        context
            A fully configured ``ssl.SSLContext``.
            Must not be ``None`` — TLS configuration
            is explicit.

        Raises
        ------
        ValueError
            If *context* is ``None`` or TLS has
            already been configured.
        """
        if context is None:
            raise ValueError(
                "SSLContext is required " "(TLS is explicit)",
            )
        if self._ssl_context is not None:
            raise ValueError(
                "TLS context already configured",
            )
        self._ssl_context = context
        self._ssl_enabled = True

    @property
    def protocol(self) -> MQTTProtocolVersion:
        """Return the MQTT protocol version (always v5)."""
        return self._protocol

    def is_connected(self) -> bool:
        """Return ``True`` if the client has an active MQTT session."""
        return self._connected

    # ============================================================
    # Connection lifecycle
    # ============================================================

    def connect_async(
        self,
        host: str,
        port: int = 1883,
        keepalive: int = 60,
        bind_address: str = "",
        bind_port: int = 0,
        clean_start: bool = True,
        properties: Properties | None = None,
    ) -> None:
        """Store connection parameters for the I/O thread.

        The actual TCP connection is established by the
        I/O thread after :meth:`loop_start` is called.

        Parameters
        ----------
        host
            The broker hostname or IPv6 address.
        port
            The broker port.
        keepalive
            The MQTT keep-alive interval in seconds.
        bind_address
            Local address to bind to (optional).
        bind_port
            Local port to bind to (optional).
        clean_start
            If ``True``, request a clean session.
        properties
            CONNECT properties to send to the broker.
        """
        if not host:
            raise ValueError("host must be non-empty")
        if port <= 0:
            raise ValueError("port must be > 0")
        if keepalive < 0:
            raise ValueError("keepalive must be >= 0")
        if bind_port < 0:
            raise ValueError("bind_port must be >= 0")
        self._host = host
        self._port = port
        self._keepalive = keepalive
        self._bind_address = bind_address
        self._bind_port = bind_port
        self._clean_start = bool(clean_start)
        self._connect_properties = properties
        self._connecting = True

    def loop_start(self) -> MQTTErrorCode:
        """Start the background I/O thread.

        Returns
        -------
        MQTTErrorCode
            :data:`MQTT_ERR_SUCCESS` on success, or
            :data:`MQTT_ERR_INVAL` if the thread is
            already running.
        """
        if self._thread is not None:
            return MQTT_ERR_INVAL
        self._thread_stop.clear()
        self._thread = threading.Thread(
            target=self._thread_main,
            name=(f"mqttv5-client-{self._client_id!r}"),
            daemon=True,
        )
        self._thread.start()
        return MQTT_ERR_SUCCESS

    def loop_stop(self) -> MQTTErrorCode:
        """Stop the background I/O thread.

        Returns
        -------
        MQTTErrorCode
            :data:`MQTT_ERR_SUCCESS` on success, or
            :data:`MQTT_ERR_INVAL` if no thread is
            running.
        """
        if self._thread is None:
            return MQTT_ERR_INVAL
        self._thread_stop.set()
        self._wakeup()
        if threading.current_thread() is not self._thread:
            self._thread.join()
        self._thread = None
        return MQTT_ERR_SUCCESS

    def disconnect(
        self,
        reasoncode: ReasonCode | None = None,
        properties: Properties | None = None,
    ) -> MQTTErrorCode:
        """Send a DISCONNECT packet to the broker.

        Parameters
        ----------
        reasoncode
            An optional reason code for the
            disconnection.
        properties
            Optional DISCONNECT properties.

        Returns
        -------
        MQTTErrorCode
            :data:`MQTT_ERR_SUCCESS` on success, or
            :data:`MQTT_ERR_NO_CONN` if not connected.
        """
        if self._sock is None:
            return MQTT_ERR_NO_CONN
        pkt = self._encode_disconnect(
            reasoncode=reasoncode,
            properties=properties,
        )
        self._queue_packet(
            PacketTypes.DISCONNECT,
            pkt,
            mid=0,
            qos=0,
        )
        self._wakeup()
        return MQTT_ERR_SUCCESS

    # ============================================================
    # Publish
    # ============================================================

    def publish(
        self,
        topic: str,
        payload: str | bytes | bytearray | int | float | None = None,
        qos: int = 1,
        retain: bool = False,
        properties: Properties | None = None,
    ) -> MQTTMessageInfo:
        """Publish a message to a topic.

        Parameters
        ----------
        topic
            The MQTT topic string.
        payload
            The message payload.  Strings are
            UTF-8 encoded; numeric types are converted
            to their ASCII representation.
        qos
            Quality of service level (1 or 2).
        retain
            If ``True``, the broker retains the message.
        properties
            Optional PUBLISH properties.

        Returns
        -------
        MQTTMessageInfo
            A result handle with the assigned message
            ID and result code.
        """
        mid = self._next_mid()
        info = MQTTMessageInfo(mid)

        if qos not in _ALLOWED_QOS:
            info.rc = MQTT_ERR_INVAL
            return info
        if self._sock is None or not self._connected:
            info.rc = MQTT_ERR_NO_CONN
            return info

        payload_b = _coerce_to_bytes(payload)
        if len(payload_b) > 268_435_455:
            info.rc = MQTT_ERR_INVAL
            return info

        with self._out_lock:
            if (
                self._max_queued_messages > 0
                and len(self._outq) >= self._max_queued_messages
            ):
                info.rc = MQTT_ERR_QUEUE_SIZE
                return info

        pkt = self._encode_publish(
            mid=mid,
            topic=topic,
            payload=payload_b,
            qos=qos,
            retain=retain,
            properties=properties,
        )

        # Track in-flight for QoS handshakes.
        self._inflight[mid] = qos
        self._queue_packet(
            PacketTypes.PUBLISH,
            pkt,
            mid=mid,
            qos=qos,
        )
        self._wakeup()
        info.rc = MQTT_ERR_SUCCESS
        return info

    # ============================================================
    # Background thread and socket handling
    # ============================================================

    def _thread_main(self) -> None:
        """Run the I/O thread entry point."""
        try:
            self._run()
        finally:
            self._close_socket()

    def _run(self) -> None:
        """Execute the connect, poll, keepalive loop."""
        self._selector = selectors.DefaultSelector()
        self._wakeup_r, self._wakeup_w = socket.socketpair()
        self._wakeup_r.setblocking(False)
        self._wakeup_w.setblocking(False)
        self._selector.register(
            self._wakeup_r,
            selectors.EVENT_READ,
            self._on_wakeup_read,
        )

        backoff = self._reconnect_min_delay
        while not self._thread_stop.is_set():
            if self._connecting and self._sock is None:
                try:
                    self._establish_connection()
                    backoff = self._reconnect_min_delay
                except OSError as exc:
                    self._log(
                        logging.WARNING,
                        "Connect failed: %s",
                        exc,
                    )
                    self._emit_connect_failed()
                    if not self._reconnect_on_failure:
                        break
                    time.sleep(backoff)
                    backoff = min(
                        backoff * 2,
                        self._reconnect_max_delay,
                    )

            self._poll_once(timeout=1.0)
            self._maybe_keepalive()

    def _poll_once(self, timeout: float) -> None:
        """Run one iteration of the selector loop."""
        if self._selector is None:
            return
        events = self._selector.select(timeout)
        for key, _mask in events:
            callback = key.data
            callback(_mask)

    def _on_wakeup_read(self, _mask: int) -> None:
        """Drain the wakeup pipe."""
        if self._wakeup_r is None:
            return
        with contextlib.suppress(BlockingIOError):
            self._wakeup_r.recv(4096)

    def _wakeup(self) -> None:
        """Signal the selector thread to wake up."""
        if self._wakeup_w is None:
            return
        with contextlib.suppress(BlockingIOError):
            self._wakeup_w.send(b"\x00")

    def _establish_connection(self) -> None:
        """Open a TCP socket, wrap TLS, send CONNECT."""
        self._close_socket()
        sock = self._open_ipv6_tcp_socket(
            host=self._host,
            port=self._port,
            timeout=self._connect_timeout,
            bind_address=self._bind_address,
            bind_port=self._bind_port,
        )
        if self._ssl_enabled:
            if self._ssl_context is None:
                raise ValueError(
                    "TLS enabled but no " "SSLContext configured",
                )
            sock = self._wrap_tls(
                sock,
                self._ssl_context,
                server_hostname=self._host,
            )
        sock.setblocking(False)
        self._sock = sock

        if self._selector is None:
            raise RuntimeError(
                "selector not initialised",
            )
        self._selector.register(
            self._sock,
            selectors.EVENT_READ,
            self._on_sock_read,
        )
        self._connected = False
        self._awaiting_pingresp = False
        self._last_in = time.monotonic()
        self._last_out = time.monotonic()

        # Send CONNECT immediately.
        connect_pkt = self._encode_connect()
        self._queue_packet(
            PacketTypes.CONNECT,
            connect_pkt,
            mid=0,
            qos=0,
        )
        self._flush_outgoing()

    @staticmethod
    def _open_ipv6_tcp_socket(
        host: str,
        port: int,
        timeout: float,
        bind_address: str,
        bind_port: int,
    ) -> socket.socket:
        """Open an IPv6-only TCP connection.

        Iterates over all ``AF_INET6`` addresses
        returned by ``getaddrinfo`` and connects to
        the first one that succeeds.

        Parameters
        ----------
        host
            The remote hostname or IPv6 address.
        port
            The remote port.
        timeout
            Connection timeout in seconds.
        bind_address
            Local address to bind to.
        bind_port
            Local port to bind to.

        Returns
        -------
        socket.socket
            A connected, non-blocking TCP socket.

        Raises
        ------
        OSError
            If no IPv6 address can be resolved or
            all connection attempts fail.
        """
        infos = socket.getaddrinfo(
            host,
            port,
            socket.AF_INET6,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
        )
        if not infos:
            raise OSError("No IPv6 address resolved")

        last_exc: OSError | None = None
        for (
            family,
            socktype,
            proto,
            _canon,
            sockaddr,
        ) in infos:
            try:
                s = socket.socket(
                    family,
                    socktype,
                    proto,
                )
                s.settimeout(timeout)
                # Enforce IPv6-only (reject v4-mapped).
                s.setsockopt(
                    socket.IPPROTO_IPV6,
                    socket.IPV6_V6ONLY,
                    1,
                )
                if bind_address or bind_port:
                    # AF_INET6 bind: (addr, port, flow, scope)
                    s.bind(
                        (
                            bind_address or "::",
                            bind_port,
                            0,
                            0,
                        ),
                    )
                s.connect(sockaddr)
                s.settimeout(None)
            except OSError as exc:
                last_exc = exc
                try:
                    s.close()
                except Exception:
                    _LOG.debug(
                        "socket close failed during" " connect teardown",
                        exc_info=True,
                    )
            else:
                return s
        raise (last_exc if last_exc is not None else OSError("IPv6 connect failed"))

    @staticmethod
    def _wrap_tls(
        sock: socket.socket,
        ctx: ssl.SSLContext,
        server_hostname: str,
    ) -> ssl.SSLSocket:
        """Wrap a TCP socket with TLS.

        Parameters
        ----------
        sock
            The connected TCP socket.
        ctx
            The TLS context.
        server_hostname
            The server hostname for SNI.

        Returns
        -------
        ssl.SSLSocket
            The TLS-wrapped socket.
        """
        return ctx.wrap_socket(
            sock,
            server_hostname=server_hostname,
            do_handshake_on_connect=True,
        )

    def _close_socket(self) -> None:
        """Close the socket and emit a disconnect event."""
        if self._selector is not None and self._sock is not None:
            try:
                self._selector.unregister(self._sock)
            except Exception:
                _LOG.debug(
                    "selector unregister failed",
                    exc_info=True,
                )
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                _LOG.debug(
                    "socket close failed",
                    exc_info=True,
                )
            self._sock = None
        if self._connected:
            self._connected = False
            self._emit_disconnect(
                packet_from_broker=False,
                reason=ReasonCode(
                    PacketTypes.DISCONNECT,
                    0,
                ),
                props=None,
            )

    # ============================================================
    # Socket read/write handlers
    # ============================================================

    def _on_sock_read(self, _mask: int) -> None:
        """Handle a readable event on the MQTT socket."""
        if self._sock is None:
            return
        try:
            data = self._sock.recv(4096)
        except (
            BlockingIOError,
            ssl.SSLWantReadError,
        ):
            return
        except OSError as exc:
            self._log(
                logging.WARNING,
                "Socket read error: %s",
                exc,
            )
            self._handle_connection_lost()
            return
        if not data:
            self._handle_connection_lost()
            return
        self._last_in = time.monotonic()
        self._process_incoming(data)

    def _handle_connection_lost(self) -> None:
        """Handle an unexpected connection loss."""
        self._log(logging.WARNING, "Connection lost")
        self._close_socket()
        self._connecting = True

    def _flush_outgoing(self) -> None:
        """Send queued packets until the socket blocks."""
        if self._sock is None:
            return
        while True:
            with self._out_lock:
                if not self._outq:
                    break
                pkt = self._outq[0]
            try:
                sent = self._sock.send(
                    pkt.data[pkt.pos :],
                )
            except (
                BlockingIOError,
                ssl.SSLWantWriteError,
                ssl.SSLWantReadError,
            ):
                break
            except OSError as exc:
                self._log(
                    logging.WARNING,
                    "Socket write error: %s",
                    exc,
                )
                self._handle_connection_lost()
                break
            if sent <= 0:
                break
            pkt.pos += sent
            self._last_out = time.monotonic()
            if pkt.pos >= len(pkt.data):
                with self._out_lock:
                    self._outq.popleft()
                # Close immediately after DISCONNECT.
                if pkt.packet_type == PacketTypes.DISCONNECT:
                    self._close_socket()
                    break

    def _queue_packet(
        self,
        packet_type: PacketTypes,
        data: bytes,
        *,
        mid: int,
        qos: int,
    ) -> None:
        """Append a packet to the outbound queue."""
        with self._out_lock:
            if (
                self._max_queued_messages > 0
                and len(self._outq) >= self._max_queued_messages
            ):
                return
            self._outq.append(
                _QueuedPacket(
                    packet_type=packet_type,
                    data=data,
                    pos=0,
                    mid=mid,
                    qos=qos,
                ),
            )

    # ============================================================
    # Incoming packet framing
    # ============================================================

    def _process_incoming(self, chunk: bytes) -> None:
        """Frame and dispatch packets from a read buffer."""
        i = 0
        while i < len(chunk):
            if i + 2 > len(chunk):
                return
            header = chunk[i]
            packet_type = PacketTypes(
                (header >> 4) & 0x0F,
            )
            i += 1
            remaining_length, n = _decode_varint(
                chunk,
                i,
            )
            i += n
            end = i + remaining_length
            if end > len(chunk):
                return
            body = chunk[i:end]
            i = end
            self._handle_packet(
                packet_type,
                header,
                body,
            )
        # After handling reads, attempt writes.
        self._flush_outgoing()

    def _handle_packet(
        self,
        packet_type: PacketTypes,
        header: int,
        body: bytes,
    ) -> None:
        """Dispatch a decoded packet to its handler."""
        if packet_type == PacketTypes.CONNACK:
            self._handle_connack(body)
            return
        if packet_type == PacketTypes.PINGRESP:
            self._awaiting_pingresp = False
            return
        if packet_type == PacketTypes.PUBACK:
            self._handle_puback(body)
            return
        if packet_type == PacketTypes.PUBREC:
            self._handle_pubrec(body)
            return
        if packet_type == PacketTypes.PUBCOMP:
            self._handle_pubcomp(body)
            return
        if packet_type == PacketTypes.DISCONNECT:
            self._handle_disconnect(body)
            return
        self._log(
            logging.DEBUG,
            "Ignoring packet type: %s",
            packet_type,
        )

    def _handle_connack(self, body: bytes) -> None:
        """Process a CONNACK packet."""
        if len(body) < 2:
            self._handle_connection_lost()
            return
        flags = body[0]
        reason = body[1]

        props = Properties(PacketTypes.CONNACK)
        try:
            props.unpack(body, offset=2)
        except Exception:
            self._log(
                logging.WARNING,
                "Malformed CONNACK properties",
            )
            self._handle_connection_lost()
            return

        if reason == 0:
            self._connected = True
            self._connecting = False
            self._reconnect_delay = None
        else:
            self._connected = False
            self._connecting = True

        self._emit_connect(
            flags=flags,
            reason=ReasonCode(
                PacketTypes.CONNACK,
                reason,
            ),
            props=props,
        )

    def _handle_disconnect(self, body: bytes) -> None:
        """Process a broker-initiated DISCONNECT."""
        reason = 0
        props = Properties(PacketTypes.DISCONNECT)
        if body:
            reason = body[0]
            try:
                props.unpack(body, offset=1)
            except Exception:
                props = Properties(
                    PacketTypes.DISCONNECT,
                )

        self._emit_disconnect(
            packet_from_broker=True,
            reason=ReasonCode(
                PacketTypes.DISCONNECT,
                reason,
            ),
            props=props,
        )
        self._close_socket()

    def _handle_puback(self, body: bytes) -> None:
        """Process a PUBACK (QoS 1 acknowledgement)."""
        if len(body) < 2:
            return
        (mid,) = struct.unpack("!H", body[:2])
        self._inflight.pop(mid, None)
        self._emit_publish(mid)

    def _handle_pubrec(self, body: bytes) -> None:
        """Process a PUBREC (QoS 2, step 2 of 4)."""
        if len(body) < 2:
            return
        (mid,) = struct.unpack("!H", body[:2])
        if self._inflight.get(mid) != 2:
            return
        pkt = self._encode_pubrel(mid)
        self._queue_packet(
            PacketTypes.PUBREL,
            pkt,
            mid=mid,
            qos=2,
        )
        self._flush_outgoing()

    def _handle_pubcomp(self, body: bytes) -> None:
        """Process a PUBCOMP (QoS 2, step 4 of 4)."""
        if len(body) < 2:
            return
        (mid,) = struct.unpack("!H", body[:2])
        self._inflight.pop(mid, None)
        self._emit_publish(mid)

    # ============================================================
    # Keepalive
    # ============================================================

    def _maybe_keepalive(self) -> None:
        """Send a PINGREQ if the connection is idle."""
        if self._sock is None or not self._connected or self._keepalive <= 0:
            return

        now = time.monotonic()
        idle = min(
            now - self._last_in,
            now - self._last_out,
        )

        if self._awaiting_pingresp:
            if now - self._last_out >= float(self._keepalive):
                self._log(
                    logging.WARNING,
                    "Keepalive timeout",
                )
                self._handle_connection_lost()
            return

        if idle >= float(self._keepalive):
            pkt = self._encode_simple(
                PacketTypes.PINGREQ,
            )
            self._queue_packet(
                PacketTypes.PINGREQ,
                pkt,
                mid=0,
                qos=0,
            )
            self._awaiting_pingresp = True
            self._flush_outgoing()

    # ============================================================
    # Encoding helpers
    # ============================================================

    def _encode_simple(
        self,
        packet_type: PacketTypes,
    ) -> bytes:
        """Encode a zero-length packet (PINGREQ, etc.)."""
        header = (packet_type.value << 4) | (_FIXED_FLAGS.get(packet_type, 0))
        return bytes([header]) + b"\x00"

    def _encode_disconnect(
        self,
        reasoncode: ReasonCode | None,
        properties: Properties | None,
    ) -> bytes:
        """Encode a DISCONNECT packet."""
        header = PacketTypes.DISCONNECT.value << 4
        if reasoncode is None and properties is None:
            return bytes([header]) + b"\x00"

        reason = (reasoncode.identifier if reasoncode is not None else 0) & 0xFF
        props = properties.pack() if properties is not None else b"\x00"
        body = bytes([reason]) + props
        return bytes([header]) + _encode_varint(len(body)) + body

    def _encode_connect(self) -> bytes:
        """Encode a CONNECT packet."""
        header = PacketTypes.CONNECT.value << 4
        proto_name = b"MQTT"
        proto_level = 5

        connect_flags = 0
        if self._clean_start:
            connect_flags |= 0x02

        if self._username is not None:
            connect_flags |= 0x80
            if self._password is not None:
                connect_flags |= 0x40

        keepalive = self._keepalive
        props = (
            self._connect_properties.pack()
            if self._connect_properties is not None
            else b"\x00"
        )

        payload = bytearray()
        payload.extend(_pack_utf8(self._client_id))

        if self._username is not None:
            payload.extend(
                _pack_utf8(self._username),
            )
            if self._password is not None:
                payload.extend(
                    _pack_utf8(self._password),
                )

        varhdr = bytearray()
        varhdr.extend(_pack_utf8(proto_name))
        varhdr.append(proto_level)
        varhdr.append(connect_flags)
        varhdr.extend(struct.pack("!H", keepalive))
        varhdr.extend(props)

        body = bytes(varhdr) + bytes(payload)
        return bytes([header]) + _encode_varint(len(body)) + body

    def _encode_publish(
        self,
        *,
        mid: int,
        topic: str,
        payload: bytes,
        qos: int,
        retain: bool,
        properties: Properties | None,
    ) -> bytes:
        """Encode a PUBLISH packet."""
        topic_b = topic.encode("utf-8")
        flags = 0
        flags |= (qos & 0x03) << 1
        if retain:
            flags |= 0x01
        header = (PacketTypes.PUBLISH.value << 4) | flags

        props = properties.pack() if properties is not None else b"\x00"

        varhdr = bytearray()
        varhdr.extend(struct.pack("!H", len(topic_b)))
        varhdr.extend(topic_b)
        varhdr.extend(struct.pack("!H", mid))
        varhdr.extend(props)

        body = bytes(varhdr) + payload
        return bytes([header]) + _encode_varint(len(body)) + body

    def _encode_pubrel(self, mid: int) -> bytes:
        """Encode a PUBREL packet (QoS 2, step 3)."""
        header = (PacketTypes.PUBREL.value << 4) | 0x02
        props = b"\x00"
        body = struct.pack("!H", mid) + props
        return bytes([header]) + _encode_varint(len(body)) + body

    # ============================================================
    # Callback emission
    # ============================================================

    def _emit_connect(
        self,
        *,
        flags: int,
        reason: ReasonCode,
        props: Properties,
    ) -> None:
        """Invoke the on_connect callback."""
        if self.on_connect is None:
            return
        try:
            connect_flags = ConnectFlags(
                session_present=bool(flags & 0x01),
            )
            self.on_connect(
                self,
                self._userdata,
                connect_flags,
                reason,
                props,
            )
        except Exception as exc:
            self._log(
                logging.ERROR,
                "on_connect raised: %s",
                exc,
            )

    def _emit_connect_failed(self) -> None:
        """Notify on connection failure."""
        return

    def _emit_disconnect(
        self,
        *,
        packet_from_broker: bool,
        reason: ReasonCode,
        props: Properties | None,
    ) -> None:
        """Invoke the on_disconnect callback."""
        if self.on_disconnect is None:
            return
        try:
            flags = DisconnectFlags(
                is_disconnect_packet_from_server=(packet_from_broker),
            )
            self.on_disconnect(
                self,
                self._userdata,
                flags,
                reason,
                props,
            )
        except Exception as exc:
            self._log(
                logging.ERROR,
                "on_disconnect raised: %s",
                exc,
            )

    def _emit_publish(self, mid: int) -> None:
        """Invoke the on_publish callback."""
        if self.on_publish is None:
            return
        try:
            self.on_publish(
                self,
                self._userdata,
                mid,
                ReasonCode(PacketTypes.PUBACK, 0),
                Properties(PacketTypes.PUBACK),
            )
        except Exception as exc:
            self._log(
                logging.ERROR,
                "on_publish raised: %s",
                exc,
            )

    def _log(
        self,
        level: int,
        fmt: str,
        *args: Any,
    ) -> None:
        """Log a message via the on_log callback and logger."""
        msg = fmt % args if args else fmt
        if self.on_log is not None:
            # Suppress all callback errors to prevent
            # recursive logging failures.
            with contextlib.suppress(Exception):
                self.on_log(
                    self,
                    self._userdata,
                    level,
                    msg,
                )
        if self._logger is not None:
            self._logger.log(level, msg)
        else:
            _LOG.log(level, msg)

    # ============================================================
    # Utility
    # ============================================================

    def _next_mid(self) -> int:
        """Allocate the next message identifier (1–65535)."""
        with self._mid_lock:
            self._last_mid += 1
            if self._last_mid > 65_535:
                self._last_mid = 1
            return self._last_mid


# ----------------------------------------------------------------
# Module-level helpers
# ----------------------------------------------------------------


def _pack_utf8(data: bytes) -> bytes:
    """Encode bytes as an MQTT UTF-8 prefixed field.

    Parameters
    ----------
    data
        The raw bytes to encode.

    Returns
    -------
    bytes
        A two-byte big-endian length prefix followed
        by *data*.

    Raises
    ------
    ValueError
        If *data* exceeds 65 535 bytes.
    """
    if len(data) > 65_535:
        raise ValueError("UTF-8 field too long")
    return struct.pack("!H", len(data)) + data


def _coerce_to_bytes(
    payload: str | bytes | bytearray | int | float | None,
) -> bytes:
    """Normalise a publish payload to bytes.

    Parameters
    ----------
    payload
        The raw payload value.  ``None`` yields an
        empty payload.  Strings are UTF-8 encoded.
        Numeric types are converted to their ASCII
        decimal representation.

    Returns
    -------
    bytes
        The encoded payload.

    Raises
    ------
    TypeError
        If *payload* is an unsupported type.
    """
    if payload is None:
        return b""
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, bytearray):
        return bytes(payload)
    if isinstance(payload, str):
        return payload.encode("utf-8")
    if isinstance(payload, (int, float)):
        return str(payload).encode("ascii")
    raise TypeError("Unsupported payload type")
