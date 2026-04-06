# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""Tests for the HTTP health endpoint module.

Covers the health server, the ``is_healthy`` probe,
configuration defaults, response codes, JSON payloads,
path routing, error handling in the status callback, and
server lifecycle (start, stop, idempotency).
"""

import datetime
import json
import threading
import unittest
import urllib.error
import urllib.request
from http import HTTPStatus

from platteklip.health import (
    _HEALTH_PATHS,
    HealthConfig,
    HealthServer,
    _build_handler,
    is_healthy,
)

_port_counter: int = 19_000


def _next_port() -> int:
    """Return a unique port for each test.

    Avoids bind collisions when tests run in parallel.
    """
    global _port_counter  # noqa: PLW0603
    _port_counter += 1
    return _port_counter


def _get(
    port: int,
    path: str,
) -> tuple[int, dict[str, object]]:
    """Issue a GET request and return status and body.

    For non-2xx responses, catches the
    :class:`urllib.error.HTTPError` and reads the body
    from the error object.
    """
    url = f"http://127.0.0.1:{port}{path}"
    try:
        with urllib.request.urlopen(
            url,
            timeout=3.0,
        ) as resp:
            body = json.loads(resp.read())
            return resp.status, body
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read())
        except json.JSONDecodeError, ValueError:
            body = {}
        finally:
            exc.close()
        return exc.code, body


# ==================================================================
# HealthConfig
# ==================================================================


class TestHealthConfig(unittest.TestCase):
    """Verify HealthConfig defaults and construction."""

    def test_defaults(self) -> None:
        """Default host is loopback, port is 8080."""
        cfg = HealthConfig()
        self.assertEqual(cfg.host, "127.0.0.1")
        self.assertEqual(cfg.port, 8080)

    def test_custom(self) -> None:
        """Accept explicit host and port values."""
        cfg = HealthConfig(host="0.0.0.0", port=9090)
        self.assertEqual(cfg.host, "0.0.0.0")
        self.assertEqual(cfg.port, 9090)

    def test_frozen(self) -> None:
        """Reject attribute mutation on frozen dataclass."""
        cfg = HealthConfig()
        with self.assertRaises(AttributeError):
            cfg.port = 1234  # type: ignore[misc]

    def test_slots(self) -> None:
        """Reject dynamic attribute creation on slots."""
        cfg = HealthConfig()
        with self.assertRaises(
            (AttributeError, TypeError),
        ):
            cfg.extra = True  # type: ignore[attr-defined]


# ==================================================================
# _build_handler
# ==================================================================


class TestBuildHandler(unittest.TestCase):
    """Verify the handler factory."""

    def test_returns_class(self) -> None:
        """Return a callable handler class."""
        handler_cls = _build_handler(
            lambda: {"healthy": True},
            __import__("logging").getLogger(),
        )
        self.assertTrue(callable(handler_cls))


# ==================================================================
# Health paths constant
# ==================================================================


class TestHealthPaths(unittest.TestCase):
    """Verify the set of recognized paths."""

    def test_contains_health_and_ready(self) -> None:
        """Include both /health and /ready."""
        self.assertIn("/health", _HEALTH_PATHS)
        self.assertIn("/ready", _HEALTH_PATHS)

    def test_is_frozenset(self) -> None:
        """Expose paths as an immutable frozenset."""
        self.assertIsInstance(
            _HEALTH_PATHS,
            frozenset,
        )


# ==================================================================
# HealthServer — lifecycle
# ==================================================================


class TestHealthServerLifecycle(unittest.TestCase):
    """Verify start/stop behaviour and idempotency."""

    def test_start_and_stop(self) -> None:
        """Start serves requests, stop shuts down."""
        port = _next_port()
        srv = HealthServer(
            status_fn=lambda: {"healthy": True},
            config=HealthConfig(port=port),
        )
        srv.start()
        try:
            self.assertTrue(is_healthy(port=port))
        finally:
            srv.stop()

    def test_start_is_idempotent(self) -> None:
        """Call start() twice without raising or rebinding."""
        port = _next_port()
        srv = HealthServer(
            status_fn=lambda: {"healthy": True},
            config=HealthConfig(port=port),
        )
        srv.start()
        srv.start()
        try:
            self.assertTrue(is_healthy(port=port))
        finally:
            srv.stop()

    def test_stop_is_idempotent(self) -> None:
        """Call stop() twice without raising."""
        port = _next_port()
        srv = HealthServer(
            status_fn=lambda: {"healthy": True},
            config=HealthConfig(port=port),
        )
        srv.start()
        srv.stop()
        srv.stop()

    def test_stop_without_start(self) -> None:
        """Call stop() without start() without raising."""
        srv = HealthServer(
            status_fn=lambda: {"healthy": True},
        )
        srv.stop()

    def test_daemon_thread(self) -> None:
        """Run the server thread as a daemon."""
        port = _next_port()
        srv = HealthServer(
            status_fn=lambda: {"healthy": True},
            config=HealthConfig(port=port),
        )
        srv.start()
        try:
            threads = {t.name: t for t in threading.enumerate()}
            self.assertIn("health-server", threads)
            self.assertTrue(
                threads["health-server"].daemon,
            )
        finally:
            srv.stop()


# ==================================================================
# HealthServer — response codes
# ==================================================================


class TestHealthServerResponses(unittest.TestCase):
    """Verify HTTP response codes and bodies."""

    def setUp(self) -> None:
        """Start a server with a controllable health flag."""
        self.port = _next_port()
        self.healthy = False
        self.srv = HealthServer(
            status_fn=lambda: {
                "healthy": self.healthy,
                "detail": "test",
            },
            config=HealthConfig(port=self.port),
        )
        self.srv.start()

    def tearDown(self) -> None:
        """Shut down the test server."""
        self.srv.stop()

    def test_unhealthy_returns_503(self) -> None:
        """Respond with 503 when healthy is False."""
        self.healthy = False
        code, body = _get(self.port, "/health")
        self.assertEqual(
            code,
            HTTPStatus.SERVICE_UNAVAILABLE,
        )
        self.assertFalse(body["healthy"])

    def test_healthy_returns_200(self) -> None:
        """Respond with 200 when healthy is True."""
        self.healthy = True
        code, body = _get(self.port, "/health")
        self.assertEqual(code, HTTPStatus.OK)
        self.assertTrue(body["healthy"])

    def test_ready_endpoint(self) -> None:
        """Serve /ready with the same logic as /health."""
        self.healthy = True
        code, body = _get(self.port, "/ready")
        self.assertEqual(code, HTTPStatus.OK)
        self.assertTrue(body["healthy"])

    def test_unknown_path_returns_404(self) -> None:
        """Reject unrecognised paths with 404."""
        code, _ = _get(self.port, "/metrics")
        self.assertEqual(code, HTTPStatus.NOT_FOUND)

    def test_root_path_returns_404(self) -> None:
        """Reject the root path with 404."""
        code, _ = _get(self.port, "/")
        self.assertEqual(code, HTTPStatus.NOT_FOUND)

    def test_body_contains_detail(self) -> None:
        """Include extra keys from the status callback."""
        self.healthy = True
        _, body = _get(self.port, "/health")
        self.assertEqual(body["detail"], "test")

    def test_content_type_is_json(self) -> None:
        """Set Content-Type to application/json."""
        self.healthy = True
        url = f"http://127.0.0.1:{self.port}/health"
        with urllib.request.urlopen(
            url,
            timeout=3.0,
        ) as resp:
            ct = resp.headers.get(
                "Content-Type",
                "",
            )
            self.assertIn("application/json", ct)

    def test_cache_control_no_store(self) -> None:
        """Set Cache-Control to no-store."""
        self.healthy = True
        url = f"http://127.0.0.1:{self.port}/health"
        with urllib.request.urlopen(
            url,
            timeout=3.0,
        ) as resp:
            cc = resp.headers.get(
                "Cache-Control",
                "",
            )
            self.assertEqual(cc, "no-store")


# ==================================================================
# HealthServer — status callback errors
# ==================================================================


class TestHealthServerCallbackErrors(unittest.TestCase):
    """Verify behaviour when status_fn raises."""

    def test_exception_returns_503(self) -> None:
        """Return 503 with an error key on callback failure."""
        port = _next_port()

        def _broken() -> dict[str, object]:
            """Raise deliberately to test error handling."""
            msg = "deliberate failure"
            raise RuntimeError(msg)

        srv = HealthServer(
            status_fn=_broken,
            config=HealthConfig(port=port),
        )
        srv.start()
        try:
            code, body = _get(port, "/health")
            self.assertEqual(
                code,
                HTTPStatus.SERVICE_UNAVAILABLE,
            )
            self.assertFalse(body["healthy"])
            self.assertIn("error", body)
        finally:
            srv.stop()


# ==================================================================
# HealthServer — dynamic state transitions
# ==================================================================


class TestHealthServerTransitions(unittest.TestCase):
    """Verify that the server reflects live state changes."""

    def test_unhealthy_to_healthy(self) -> None:
        """Transition from 503 to 200 on state change."""
        port = _next_port()
        state: dict[str, object] = {
            "healthy": False,
        }

        srv = HealthServer(
            status_fn=lambda: dict(state),
            config=HealthConfig(port=port),
        )
        srv.start()
        try:
            code, _ = _get(port, "/health")
            self.assertEqual(
                code,
                HTTPStatus.SERVICE_UNAVAILABLE,
            )

            state["healthy"] = True
            code, _ = _get(port, "/health")
            self.assertEqual(code, HTTPStatus.OK)
        finally:
            srv.stop()

    def test_healthy_to_unhealthy(self) -> None:
        """Transition from 200 to 503 on state change."""
        port = _next_port()
        state: dict[str, object] = {
            "healthy": True,
        }

        srv = HealthServer(
            status_fn=lambda: dict(state),
            config=HealthConfig(port=port),
        )
        srv.start()
        try:
            code, _ = _get(port, "/health")
            self.assertEqual(code, HTTPStatus.OK)

            state["healthy"] = False
            code, _ = _get(port, "/health")
            self.assertEqual(
                code,
                HTTPStatus.SERVICE_UNAVAILABLE,
            )
        finally:
            srv.stop()


# ==================================================================
# HealthServer — missing "healthy" key
# ==================================================================


class TestHealthServerMissingKey(unittest.TestCase):
    """Verify that a missing healthy key means unhealthy."""

    def test_no_healthy_key_returns_503(self) -> None:
        """Treat absent healthy key as unhealthy."""
        port = _next_port()
        srv = HealthServer(
            status_fn=lambda: {"uptime": 42},
            config=HealthConfig(port=port),
        )
        srv.start()
        try:
            code, body = _get(port, "/health")
            self.assertEqual(
                code,
                HTTPStatus.SERVICE_UNAVAILABLE,
            )
            self.assertEqual(body["uptime"], 42)
        finally:
            srv.stop()


# ==================================================================
# HealthServer — non-serialisable values
# ==================================================================


class TestHealthServerSerialisation(unittest.TestCase):
    """Verify the default=str fallback for non-JSON types."""

    def test_datetime_in_status(self) -> None:
        """Serialise datetime via the str fallback."""
        port = _next_port()
        srv = HealthServer(
            status_fn=lambda: {
                "healthy": True,
                "checked_at": datetime.datetime(
                    2025,
                    1,
                    1,
                    tzinfo=datetime.UTC,
                ),
            },
            config=HealthConfig(port=port),
        )
        srv.start()
        try:
            code, body = _get(port, "/health")
            self.assertEqual(code, HTTPStatus.OK)
            self.assertIn(
                "2025",
                str(body["checked_at"]),
            )
        finally:
            srv.stop()


# ==================================================================
# is_healthy probe function
# ==================================================================


class TestIsHealthy(unittest.TestCase):
    """Verify the is_healthy probe function."""

    def test_returns_true_when_healthy(self) -> None:
        """Return True for a 200 response."""
        port = _next_port()
        srv = HealthServer(
            status_fn=lambda: {"healthy": True},
            config=HealthConfig(port=port),
        )
        srv.start()
        try:
            self.assertTrue(is_healthy(port=port))
        finally:
            srv.stop()

    def test_returns_false_when_unhealthy(self) -> None:
        """Return False for a 503 response."""
        port = _next_port()
        srv = HealthServer(
            status_fn=lambda: {"healthy": False},
            config=HealthConfig(port=port),
        )
        srv.start()
        try:
            self.assertFalse(
                is_healthy(port=port),
            )
        finally:
            srv.stop()

    def test_returns_false_when_unreachable(self) -> None:
        """Return False when no server is listening."""
        self.assertFalse(
            is_healthy(
                port=19_999,
                timeout=0.5,
            ),
        )

    def test_custom_host(self) -> None:
        """Accept an explicit host parameter."""
        port = _next_port()
        srv = HealthServer(
            status_fn=lambda: {"healthy": True},
            config=HealthConfig(port=port),
        )
        srv.start()
        try:
            self.assertTrue(
                is_healthy(
                    port=port,
                    host="127.0.0.1",
                ),
            )
        finally:
            srv.stop()


if __name__ == "__main__":
    unittest.main()
