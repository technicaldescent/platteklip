# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""Lightweight HTTP health endpoint using the stdlib.

Runs an :class:`http.server.HTTPServer` in a daemon
thread, exposing ``/health`` and ``/ready`` endpoints
that report application liveness via a caller-supplied
status callback.

The server is deliberately minimal: no TLS, no routing
framework, no external dependencies.  It binds to the
loopback interface by default so that only the
container's own healthcheck can reach it.

Typical usage::

    from platteklip.health import HealthServer

    def _status() -> dict[str, object]:
        return {
            "connected": producer.is_connected,
            "published": (
                producer.stats.published_accepted
            ),
        }

    server = HealthServer(
        status_fn=_status, port=8080,
    )
    server.start()

    # ... application runs ...

    server.stop()
"""

import http.client
import json
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass
from http import HTTPStatus
from http.server import (
    BaseHTTPRequestHandler,
    HTTPServer,
)
from typing import Final

logger: Final[logging.Logger] = logging.getLogger(
    __name__,
)

_HEALTH_PATHS: Final[frozenset[str]] = frozenset(
    {"/health", "/ready"},
)


@dataclass(frozen=True, slots=True)
class HealthConfig:
    """Health server binding configuration.

    Parameters
    ----------
    host
        Interface to bind to.  Defaults to the IPv4
        loopback address so the endpoint is only
        reachable from inside the container.
    port
        TCP port to listen on.
    """

    host: str = "127.0.0.1"
    port: int = 8080


class HealthServer:
    """HTTP health endpoint backed by a daemon thread.

    The server responds to ``GET /health`` and
    ``GET /ready`` with a JSON body produced by
    *status_fn*.  If the body contains a truthy
    ``"healthy"`` key the response code is
    ``200 OK``; otherwise ``503 Service Unavailable``.

    All other paths receive ``404 Not Found``.

    Parameters
    ----------
    status_fn
        Zero-argument callable that returns a ``dict``
        suitable for :func:`json.dumps`.  Called on
        every request, so it must be fast and
        thread-safe.
    config
        Binding address and port.
    log
        Override the module-level logger.
    """

    def __init__(
        self,
        *,
        status_fn: Callable[[], dict[str, object]],
        config: HealthConfig | None = None,
        log: logging.Logger | None = None,
    ) -> None:
        """Initialise the health server."""
        self._status_fn: Final = status_fn
        self._config: Final = config or HealthConfig()
        self._log: Final = log or logger
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the health server in a daemon thread.

        Safe to call multiple times; subsequent calls
        are no-ops.
        """
        if self._thread is not None:
            return

        handler = _build_handler(
            self._status_fn,
            self._log,
        )

        self._server = HTTPServer(
            (self._config.host, self._config.port),
            handler,
        )

        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="health-server",
            daemon=True,
        )
        self._thread.start()

        self._log.info(
            "Health server listening on %s:%d",
            self._config.host,
            self._config.port,
        )

    def stop(self) -> None:
        """Shut down the server and release resources.

        Idempotent.  The correct teardown sequence is:

        1. ``HTTPServer.shutdown`` signals
           ``serve_forever`` to exit its polling loop.
        2. ``Thread.join`` waits for the server thread
           to finish.
        3. ``HTTPServer.server_close`` closes the
           listening socket.

        Calling ``server_close`` before ``shutdown``
        closes the socket under a running
        ``serve_forever`` loop and produces
        ``ResourceWarning`` on finalisation.
        """
        if self._server is not None:
            self._server.shutdown()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        if self._server is not None:
            self._server.server_close()
            self._server = None


def _build_handler(
    status_fn: Callable[[], dict[str, object]],
    log: logging.Logger,
) -> type[BaseHTTPRequestHandler]:
    """Build a request handler closed over *status_fn*.

    This factory pattern is necessary because
    :class:`HTTPServer` instantiates the handler class
    per-request with a fixed constructor signature.

    Parameters
    ----------
    status_fn
        The health status callback.
    log
        Logger for request-level diagnostics.

    Returns
    -------
    type[BaseHTTPRequestHandler]
        A handler class ready for use with
        :class:`HTTPServer`.
    """

    class _Handler(BaseHTTPRequestHandler):
        """Per-request HTTP handler."""

        def do_GET(self) -> None:
            """Route GET requests to health or 404."""
            if self.path not in _HEALTH_PATHS:
                self.send_error(
                    HTTPStatus.NOT_FOUND,
                )
                return

            try:
                status = status_fn()
            except Exception:
                log.warning(
                    "status_fn raised",
                    exc_info=True,
                )
                status = {
                    "healthy": False,
                    "error": "status callback failed",
                }

            healthy = bool(
                status.get("healthy", False),
            )

            code = HTTPStatus.OK if healthy else HTTPStatus.SERVICE_UNAVAILABLE

            body = json.dumps(
                status,
                default=str,
                ensure_ascii=False,
            ).encode("utf-8")

            self.send_response(code)
            self.send_header(
                "Content-Type",
                "application/json; charset=utf-8",
            )
            self.send_header(
                "Content-Length",
                str(len(body)),
            )
            self.send_header(
                "Cache-Control",
                "no-store",
            )
            self.end_headers()
            self.wfile.write(body)

        def log_message(
            self,
            format: str,  # noqa: A002
            *args: object,
        ) -> None:
            """Suppress default stderr logging."""

    return _Handler


def is_healthy(
    port: int = 8080,
    *,
    host: str = "127.0.0.1",
    timeout: float = 3.0,
) -> bool:
    r"""Probe the local health endpoint.

    Use :class:`http.client.HTTPConnection` directly,
    scoped to plain HTTP with no support for arbitrary
    URL schemes.

    Intended for use in container healthcheck commands::

        python -c \
          "from platteklip.health import is_healthy;\
           raise SystemExit(0 if is_healthy() else 1)"

    Parameters
    ----------
    port
        Port the health server listens on.
    host
        Host to connect to.
    timeout
        HTTP request timeout in seconds.

    Returns
    -------
    bool
        ``True`` if the endpoint returned ``200 OK``.
    """
    conn = http.client.HTTPConnection(
        host,
        port,
        timeout=timeout,
    )
    try:
        conn.request("GET", "/health")
        resp = conn.getresponse()
    except Exception:
        return False
    else:
        return resp.status == HTTPStatus.OK
    finally:
        conn.close()
