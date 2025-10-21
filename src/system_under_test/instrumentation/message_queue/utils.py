# SPDX-FileCopyrightText: 2025 system-under-test contributors
# SPDX-License-Identifier: Apache-2.0

"""
OpenTelemetry configuration module for traces, metrics, and logs.

This module initialises OpenTelemetry SDK providers and exporters
according to the OpenTelemetry Specification 1.49.0.
"""

import logging
import os

from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import (
    OTLPLogExporter,
)
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
    OTLPMetricExporter,
)
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
    OTLPSpanExporter,
)
from opentelemetry.instrumentation.logging import LoggingInstrumentor
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import (
    SERVICE_NAME,
    SERVICE_VERSION,
    TELEMETRY_SDK_LANGUAGE,
    TELEMETRY_SDK_NAME,
    TELEMETRY_SDK_VERSION,
    Resource,
)
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

logger = logging.getLogger(__name__)


def setup_telemetry() -> None:
    """
    Configure OpenTelemetry providers for traces, metrics, and logs.

    This function initialises the OpenTelemetry SDK with OTLP exporters
    for all three signals (traces, metrics, logs) and configures the
    Python logging system to emit structured logs with trace context.

    Environment Variables:
        OTEL_SDK_DISABLED: Disable the SDK entirely ("true" or "1")
        OTEL_EXPORTER_OTLP_ENDPOINT: OTLP endpoint URL (required)
        OTEL_EXPORTER_OTLP_INSECURE: Use insecure gRPC ("true" or "1")
        OTEL_SERVICE_NAME: Service name for resource attributes
        OTEL_SERVICE_VERSION: Service version for resource attributes
        OTEL_DEPLOYMENT_ENVIRONMENT: Deployment environment
        LOG_LEVEL: Python logging level (default: INFO)
        OTEL_PYTHON_LOG_LEVEL: OpenTelemetry log level (default: INFO)

    Raises:
        None: Logs warnings/errors but does not raise exceptions.
    """
    if os.getenv("OTEL_SDK_DISABLED", "false").lower() in ("true", "1"):
        logger.info("OpenTelemetry SDK is disabled via OTEL_SDK_DISABLED.")
        return

    otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not otlp_endpoint:
        logger.warning(
            "OTEL_EXPORTER_OTLP_ENDPOINT is not set; " "telemetry will not be exported."
        )
        return

    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Create resource with required and recommended attributes
    resource = Resource.create(
        {
            SERVICE_NAME: os.getenv("OTEL_SERVICE_NAME", "unknown_service"),
            SERVICE_VERSION: os.getenv("OTEL_SERVICE_VERSION", "1.49.0"),
            "deployment.environment": os.getenv(
                "OTEL_DEPLOYMENT_ENVIRONMENT", "development"
            ),
            TELEMETRY_SDK_NAME: "opentelemetry",
            TELEMETRY_SDK_LANGUAGE: "python",
            TELEMETRY_SDK_VERSION: "1.49.0",
        }
    )

    use_insecure = os.getenv("OTEL_EXPORTER_OTLP_INSECURE", "false").lower() in (
        "true",
        "1",
    )

    # Configure Tracing
    trace_provider = TracerProvider(resource=resource)
    trace_exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=use_insecure)
    trace_provider.add_span_processor(BatchSpanProcessor(trace_exporter))
    trace.set_tracer_provider(trace_provider)

    # Configure Metrics
    metric_exporter = OTLPMetricExporter(endpoint=otlp_endpoint, insecure=use_insecure)
    metric_reader = PeriodicExportingMetricReader(
        exporter=metric_exporter, export_interval_millis=5000
    )
    meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
    metrics.set_meter_provider(meter_provider)

    # Configure Logging
    logger_provider = LoggerProvider(resource=resource)
    log_exporter = OTLPLogExporter(endpoint=otlp_endpoint, insecure=use_insecure)
    logger_provider.add_log_record_processor(BatchLogRecordProcessor(log_exporter))

    # Attach logging handler to root logger for OTLP export
    logging_handler = LoggingHandler(
        level=logging.NOTSET, logger_provider=logger_provider
    )
    logging.getLogger().addHandler(logging_handler)

    # Instrument the standard logging library for trace context injection
    LoggingInstrumentor().instrument(
        set_logging_format=True,
        log_level=logging.getLevelName(
            os.getenv("OTEL_PYTHON_LOG_LEVEL", "INFO").upper()
        ),
    )

    service_name = resource.attributes.get(SERVICE_NAME, "unknown")
    logger.info(f"Telemetry configured for service '{service_name}'")
    logger.info(f"  - OTLP Endpoint: {otlp_endpoint}")
    logger.info(f"  - Insecure gRPC: {use_insecure}")
    logger.info(f"  - Resource: {dict(resource.attributes)}")  # noqa: C408
