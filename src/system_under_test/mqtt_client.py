# SPDX-FileCopyrightText: 2025 tradecraft contributors
# SPDX-License-Identifier: Apache-2.0

"""
MQTT telemetry signal generator with OpenTelemetry instrumentation.

This module simulates a machine generating motor telemetry signals and
publishes them to an MQTT broker with distributed tracing support.
Implements OpenTelemetry Specification semantic conventions for
messaging systems.
"""

import asyncio
import json
import logging
import os
import random
import secrets
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

import paho.mqtt.client as mqtt
from opentelemetry import metrics, trace
from opentelemetry.metrics import CallbackOptions, Observation
from opentelemetry.propagate import inject
from opentelemetry.trace import SpanKind, Status, StatusCode

logger = logging.getLogger(__name__)


class SignalGenerator:
    """
    Generate and publish telemetry representing a simulated machine.

    This class creates a simulated industrial machine that generates motor
    telemetry (temperature and current) and publishes it to an MQTT broker.
    All operations are instrumented with OpenTelemetry traces and metrics.
    """

    MACHINE_ID = os.getenv("MACHINE_ID", "CM-4321")
    MOTOR_IDS = [
        "cutter_left",
        "cutter_right",
        "gathering_head_left",
        "gathering_head_right",
        "traction_left",
        "traction_right",
        "conveyor",
        "hydraulic",
        "dust_fan",
    ]
    TOPIC_PREFIX = "operations/telemetry"
    MQTT_PROTOCOL_VERSION = "5.0.0"

    def __init__(self, mqtt_host: str, mqtt_port: int) -> None:
        """
        Initialise the signal generator.

        Args:
            mqtt_host: MQTT broker hostname or IP address.
            mqtt_port: MQTT broker port number.
        """
        self.mqtt_host = mqtt_host
        self.mqtt_port = mqtt_port
        self.connected_event = asyncio.Event()

        self.mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self.mqtt_client.on_connect = self._on_connect
        self.mqtt_client.on_disconnect = self._on_disconnect

        # Set up a secure, high-entropy RNG
        seed = secrets.randbits(256)
        self.rng = random.Random(seed)

        # Store latest sensor readings for observable gauge callbacks
        self._latest_temps: dict[str, float] = {}
        self._latest_currents: dict[str, float] = {}

        # Initialise OpenTelemetry instruments
        meter = metrics.get_meter(__name__)

        self.messages_published_counter = meter.create_counter(
            name="messaging.publish.messages",
            description=("Number of messages published to the messaging system."),
            unit="{message}",
        )

        # Create observable gauges with callbacks for motor telemetry
        meter.create_observable_gauge(
            name="machine.motor.temperature",
            callbacks=[self._temperature_callback],
            description="Current temperature of a motor.",
            unit="Cel",
        )

        meter.create_observable_gauge(
            name="machine.motor.current",
            callbacks=[self._current_callback],
            description="Current electrical current draw of a motor.",
            unit="A",
        )

    def _temperature_callback(self, options: CallbackOptions) -> Iterable[Observation]:
        """
        Provide motor temperature observations for the gauge.

        Args:
            options: Callback options from the metrics SDK.

        Yields:
            Observation: Temperature observations for each motor.
        """
        for motor_id, temp in self._latest_temps.items():
            yield Observation(
                temp, {"motor.id": motor_id, "machine.id": self.MACHINE_ID}
            )

    def _current_callback(self, options: CallbackOptions) -> Iterable[Observation]:
        """
        Provide motor current observations for the gauge.

        Args:
            options: Callback options from the metrics SDK.

        Yields:
            Observation: Current observations for each motor.
        """
        for motor_id, current in self._latest_currents.items():
            yield Observation(
                current, {"motor.id": motor_id, "machine.id": self.MACHINE_ID}
            )

    def _create_payload(
        self,
        name: str,
        value: Any,
        unit: str,
        attributes: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Create a standardised telemetry payload for MQTT.

        Args:
            name: Metric or signal name.
            value: Measured value.
            unit: Unit of measurement (UCUM recommended).
            attributes: Additional attributes for the measurement.

        Returns:
            dict: Formatted payload ready for JSON serialisation.
        """
        payload: dict[str, Any] = {
            "name": name,
            "value": value,
            "unit": unit,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attributes": attributes or {},
        }
        payload["attributes"]["machine.id"] = self.MACHINE_ID
        return payload

    def _on_connect(
        self,
        client: mqtt.Client,
        userdata: Any,
        flags: mqtt.ConnectFlags,
        rc: mqtt.ReasonCode,
        properties: mqtt.Properties | None = None,
    ) -> None:
        """
        Handle MQTT client connection to broker.

        Args:
            client: MQTT client instance.
            userdata: User data passed to client.
            flags: Response flags from broker.
            rc: Connection result code.
            properties: MQTT v5 properties (optional).
        """
        if rc == 0:
            logger.info("Machine communication system connected to MQTT broker")
            self.connected_event.set()
        else:
            logger.error(f"Machine connection failed, code {rc}")
            self.connected_event.clear()

    def _on_disconnect(
        self,
        client: mqtt.Client,
        userdata: Any,
        flags: mqtt.DisconnectFlags,
        rc: mqtt.ReasonCode,
        properties: mqtt.Properties | None = None,
    ) -> None:
        """
        Handle MQTT client disconnection from broker.

        Args:
            client: MQTT client instance.
            userdata: User data passed to client.
            flags: Disconnection flags from broker.
            rc: Disconnection result code.
            properties: MQTT v5 properties (optional).
        """
        logger.warning(f"Machine disconnected from MQTT broker, code {rc}")
        self.connected_event.clear()

    async def connect(self) -> None:
        """
        Connect the machine's communication system to the MQTT broker.

        Creates a CLIENT span for the connection operation following
        OpenTelemetry semantic conventions for messaging systems.

        Raises:
            Exception: If connection fails after timeout.
        """
        if self.connected_event.is_set():
            return

        logger.info(f"Connecting to {self.mqtt_host}:{self.mqtt_port}...")
        tracer = trace.get_tracer(__name__)

        with tracer.start_as_current_span("connect", kind=SpanKind.CLIENT) as span:
            span.set_attribute("messaging.system", "mqtt")
            span.set_attribute("server.address", self.mqtt_host)
            span.set_attribute("server.port", self.mqtt_port)
            span.set_attribute("network.protocol.name", "mqtt")
            span.set_attribute("network.protocol.version", self.MQTT_PROTOCOL_VERSION)
            span.set_attribute("machine.id", self.MACHINE_ID)

            try:
                self.mqtt_client.connect(self.mqtt_host, self.mqtt_port, 60)
                self.mqtt_client.loop_start()
                await asyncio.wait_for(self.connected_event.wait(), timeout=10)
                logger.info("Connection confirmed")
            except Exception as e:
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR))
                logger.error("Failed to connect", exc_info=e)
                self.mqtt_client.loop_stop()
                raise

    async def disconnect(self) -> None:
        """Disconnect from the MQTT broker."""
        if self.connected_event.is_set():
            self.mqtt_client.loop_stop()
            self.mqtt_client.disconnect()
            logger.info("Disconnection initiated")

    def is_message_published(self, topic: str, payload: dict[str, Any]) -> bool:
        """
        Publish a JSON payload to an MQTT topic with distributed tracing.

        Creates a PRODUCER span and injects trace context into the message
        payload to enable distributed tracing across the MQTT broker and
        consumers.

        Args:
            topic: MQTT topic to publish to.
            payload: Dictionary payload to serialise as JSON.

        Returns:
            bool: True if publish succeeded, False otherwise.
        """
        if not self.connected_event.is_set():
            logger.warning("Not connected, cannot publish message")
            return False

        tracer = trace.get_tracer(__name__)

        with tracer.start_as_current_span("publish", kind=SpanKind.PRODUCER) as span:
            span.set_attribute("messaging.system", "mqtt")
            span.set_attribute("messaging.operation.type", "publish")
            span.set_attribute("messaging.destination.name", topic)
            span.set_attribute("machine.id", self.MACHINE_ID)

            try:
                # Inject trace context into payload for distributed tracing
                carrier: dict[str, Any] = {}
                inject(carrier)
                payload["_otel_trace_context"] = carrier

                message = json.dumps(payload)
                result = self.mqtt_client.publish(topic, message)

                if result.rc == mqtt.MQTT_ERR_SUCCESS:
                    self.messages_published_counter.add(
                        1,
                        {
                            "messaging.system": "mqtt",
                            "messaging.destination.name": topic,
                            "messaging.operation.type": "publish",
                            "machine.id": self.MACHINE_ID,
                        },
                    )
                    logger.debug(
                        f"Published message to topic: {topic} " f"with trace context"
                    )
                    return True
                else:
                    logger.warning(f"Publish to {topic} returned code: {result.rc}")
                    return False

            except Exception as e:
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR))
                logger.error("Failed to publish MQTT message", exc_info=e)
                return False

    def generate_diagnostic_fault(self) -> None:
        """
        Generate a diagnostic fault event as a structured log.

        Faults are modelled as ERROR level logs with structured attributes
        following OpenTelemetry semantic conventions for exceptions.
        """
        if self.rng.random() < 0.05:  # 5% chance of fault
            log_attributes = {
                "log.record.uid": str(uuid.uuid4()),
                "exception.type": "E-102",
                "exception.message": "Hydraulic pressure exceeds safe limits.",
                "machine.id": self.MACHINE_ID,
            }
            logger.error(
                "Fault Detected: Hydraulic System Overpressure",
                extra={"attributes": log_attributes},
            )

    def generate_motor_signals(self) -> None:
        """
        Generate motor signals and publish them via MQTT and OTel metrics.

        Creates a PRODUCER span for the entire batch operation and publishes
        temperature and current readings for each motor. Updates internal
        state for observable gauge callbacks.
        """
        tracer = trace.get_tracer(__name__)

        with tracer.start_as_current_span(
            "generate.motor.signals", kind=SpanKind.PRODUCER
        ) as batch_span:
            batch_span.set_attribute("messaging.system", "mqtt")
            batch_span.set_attribute(
                "messaging.batch.message_count", len(self.MOTOR_IDS)
            )
            batch_span.set_attribute("machine.id", self.MACHINE_ID)

            for motor_id in self.MOTOR_IDS:
                # Generate temperature signal
                temp = round(self.rng.uniform(40, 95), 1)
                self._latest_temps[motor_id] = temp

                temp_payload = self._create_payload(
                    "machine.motor.temperature",
                    temp,
                    "Cel",
                    {"motor.id": motor_id},
                )
                self.is_message_published(
                    f"{self.TOPIC_PREFIX}/motor/{motor_id}/temperature",
                    temp_payload,
                )

                # Generate current signal
                current = round(self.rng.uniform(15, 60), 1)
                self._latest_currents[motor_id] = current

                current_payload = self._create_payload(
                    "machine.motor.current",
                    current,
                    "A",
                    {"motor.id": motor_id},
                )
                self.is_message_published(
                    f"{self.TOPIC_PREFIX}/motor/{motor_id}/current",
                    current_payload,
                )

    async def run_all_generators(self) -> None:
        """
        Execute the main machine work cycle loop.

        Continuously generates telemetry signals and publishes them to MQTT
        with a 5-second interval between cycles. Handles reconnection logic
        if connection is lost.

        Raises:
            asyncio.CancelledError: When shutdown is requested.
        """
        try:
            while True:
                if not self.connected_event.is_set():
                    logger.info("Reconnecting communication system...")
                    try:
                        await self.connect()
                    except Exception:
                        logger.error("Reconnect failed. Retrying in 5s...")
                        await asyncio.sleep(5)
                        continue

                logger.info("Starting new machine work cycle...")
                tracer = trace.get_tracer(__name__)

                with tracer.start_as_current_span(
                    "machine.work_cycle", kind=SpanKind.INTERNAL
                ) as span:
                    span.set_attribute("machine.id", self.MACHINE_ID)

                    self.generate_diagnostic_fault()
                    self.generate_motor_signals()

                logger.info("Work cycle complete. Idling for 5 seconds...")
                await asyncio.sleep(5)

        except asyncio.CancelledError:
            logger.info("Machine shutdown signal received.")
        finally:
            await self.disconnect()


async def main() -> None:
    """
    Run the main entry point for the MQTT telemetry simulator.

    Initialises OpenTelemetry and starts the signal generator.
    """
    from system_under_test.instrumentation.message_queue import utils

    utils.setup_telemetry()

    mqtt_host = os.getenv("MQTT_HOST", "localhost")
    mqtt_port = int(os.getenv("MQTT_PORT", 1883))

    logger.info(f"Initialising machine simulator: {SignalGenerator.MACHINE_ID}")
    generator = SignalGenerator(mqtt_host, mqtt_port)
    await generator.run_all_generators()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Simulator stopped by user.")
