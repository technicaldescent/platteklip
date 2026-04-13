# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""Centralised OpenTelemetry provider configuration.

Configures trace, metric, and log providers with OTLP/gRPC
exporters.  All providers read connection parameters from the
standard ``OTEL_EXPORTER_*`` environment variables.

The :func:`configure_telemetry` entry point must be called
once, before any tracer, meter, or logger is used.  The
matching :func:`shutdown_telemetry` flushes pending
telemetry and releases resources.

Logging integration
-------------------
A :class:`~opentelemetry.sdk._logs.LoggingHandler` is
attached to the ``platteklip`` logger namespace so that
every stdlib ``logging`` call within that namespace is
automatically forwarded to the OTel log pipeline.  Trace
context (``trace_id``, ``span_id``) is injected into each
log record when the call occurs inside an active span.

The handler is attached to ``platteklip`` rather than the
root logger to avoid capturing third-party library noise.
"""

import logging
import os
from typing import Final

from opentelemetry import metrics, trace
from opentelemetry._logs import set_logger_provider
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import (
    OTLPLogExporter,
)
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
    OTLPMetricExporter,
)
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
    OTLPSpanExporter,
)
from opentelemetry.instrumentation.logging import (
    LoggingInstrumentor,
)
from opentelemetry.sdk._logs import (
    LoggerProvider,
    LoggingHandler,
)
from opentelemetry.sdk._logs.export import (
    BatchLogRecordProcessor,
)
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import (
    PeriodicExportingMetricReader,
)
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
)

_NAMESPACE: Final[str] = "platteklip"

_logger_provider: LoggerProvider | None = None
_tracer_provider: TracerProvider | None = None
_meter_provider: MeterProvider | None = None


def _build_resource() -> Resource:
    """Construct the OTel resource descriptor.

    Reads ``OTEL_SERVICE_NAME`` and ``HOST_NAME`` from
    the environment to populate the ``service.name`` and
    ``service.instance.id`` attributes respectively.

    Returns
    -------
    Resource
        Merged resource suitable for all providers.
    """
    return Resource.create(
        {
            "service.name": os.getenv(
                "OTEL_SERVICE_NAME",
                _NAMESPACE,
            ),
            "service.instance.id": os.getenv(
                "HOST_NAME",
                "unknown",
            ),
        },
    )


def configure_telemetry() -> None:
    """Initialise trace, metric, and log providers.

    Each provider is configured with an OTLP/gRPC exporter
    that reads endpoints, TLS, and authentication from the
    standard ``OTEL_EXPORTER_*`` environment variables.

    A :class:`LoggingHandler` is attached to the
    ``platteklip`` logger namespace.  The
    :class:`LoggingInstrumentor` injects ``otelTraceID``,
    ``otelSpanID``, and ``otelServiceName`` into every
    :class:`logging.LogRecord`, making them available to
    console formatters as well as the OTLP pipeline.

    This function is idempotent; repeated calls are
    silently ignored.
    """
    global _logger_provider  # noqa: PLW0603
    global _tracer_provider  # noqa: PLW0603
    global _meter_provider  # noqa: PLW0603

    if _tracer_provider is not None:
        return

    resource = _build_resource()

    # -- Traces ---------------------------------------------

    _tracer_provider = TracerProvider(
        resource=resource,
    )
    _tracer_provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter()),
    )
    trace.set_tracer_provider(_tracer_provider)

    # -- Metrics --------------------------------------------

    reader = PeriodicExportingMetricReader(
        OTLPMetricExporter(),
    )
    _meter_provider = MeterProvider(
        resource=resource,
        metric_readers=[reader],
    )
    metrics.set_meter_provider(_meter_provider)

    # -- Logs -----------------------------------------------

    _logger_provider = LoggerProvider(
        resource=resource,
    )
    _logger_provider.add_log_record_processor(
        BatchLogRecordProcessor(OTLPLogExporter()),
    )
    set_logger_provider(_logger_provider)

    handler = LoggingHandler(
        level=logging.NOTSET,
        logger_provider=_logger_provider,
    )

    # Attach to the application namespace only.
    # The root logger keeps its console handler
    # untouched so local output is unaffected.
    ns_logger = logging.getLogger(_NAMESPACE)
    ns_logger.addHandler(handler)

    # Inject trace context fields into every LogRecord
    # so that console formatters can include them.
    LoggingInstrumentor().instrument(
        set_logging_format=True,
    )


def shutdown_telemetry() -> None:
    """Flush pending telemetry and release resources.

    Safe to call even if :func:`configure_telemetry` was
    never invoked.
    """
    global _logger_provider  # noqa: PLW0603
    global _tracer_provider  # noqa: PLW0603
    global _meter_provider  # noqa: PLW0603

    if _logger_provider is not None:
        _logger_provider.shutdown()
        _logger_provider = None

    if _meter_provider is not None:
        _meter_provider.shutdown()
        _meter_provider = None

    if _tracer_provider is not None:
        _tracer_provider.shutdown()
        _tracer_provider = None
