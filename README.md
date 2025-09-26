<!--
# SPDX-FileCopyrightText: 2025 system-under-test contributors
# SPDX-License-Identifier: CC-BY-4.0
-->

-----

# Observability Reference Architecture

A secure, containerised platform for monitoring event-driven systems.

-----

## Table of Contents

  - [About The Project](https://www.google.com/search?q=%23about-the-project)
  - [Guiding Principles](https://www.google.com/search?q=%23guiding-principles)
  - [System Architecture](https://www.google.com/search?q=%23system-architecture)
  - [Getting Started](https://www.google.com/search?q=%23getting-started)
  - [Contributing](https://www.google.com/search?q=%23contributing)
  - [License](https://www.google.com/search?q=%23license)

-----

## About The Project

This project provides a comprehensive, production-ready blueprint for building a highly secure and observable backend system. It integrates a complete telemetry pipeline based on **OpenTelemetry** with event-driven messaging systems like **Kafka** and **MQTT**.

The primary goals are:

  - **To provide a reference implementation** for monitoring complex, distributed applications using open standards.
  - **To demonstrate security-first principles** in a containerised environment, adhering to benchmarks like the CIS Docker Benchmark and NIST guidelines.
  - **To support resilience and long-term maintainability** through a decoupled architecture and careful component selection.

-----

## Guiding Principles

This project is opinionated and adheres to a set of core principles that lead to more robust, secure, and maintainable systems.

  - **Security by Design**: The entire stack is hardened by default. This includes running containers as non-root users, using read-only filesystems, dropping unnecessary kernel capabilities, enforcing resource limits, and segmenting network traffic.
  - **Comprehensive Observability**: We implement the three pillars of observability. All telemetry data (logs, metrics, and traces) is generated and collected using the vendor-neutral **OpenTelemetry** standard, ensuring deep introspection into the system's behaviour.
  - **Resilient & Asynchronous Communication**: The architecture is built around event-driven principles, using **MQTT** for real-time messaging and **Apache Kafka** as a durable, high-throughput message bus for critical data like logs.

-----

## System Architecture

The stack is composed of several services working in concert. The `compose.yaml` file defines how they are orchestrated.

| Category                  | Service                               | Role in the Stack                                                                      |
| ------------------------- | ------------------------------------- | -------------------------------------------------------------------------------------- |
| **Application** | `mqtt-client`                         | The example application being monitored, instrumented with OpenTelemetry.              |
| **Access & Security** | `nginx`                               | Secure reverse proxy and entry point for all external traffic.                         |
|                           | `keycloak` & `keycloak-postgres`      | Provides centralised Identity and Access Management (IAM).                             |
| **Messaging** | `mqtt-broker`                         | Lightweight broker for real-time pub/sub messaging.                                    |
|                           | `kafka` & `kafdrop`                   | High-throughput, persistent event streaming platform and a web UI for management.    |
| **Telemetry Pipeline** | `otel-collector`                      | Central aggregator that receives, processes, and exports telemetry data.               |
|                           | `jaeger`                              | Stores and visualises distributed traces.                                              |
|                           | `prometheus`                          | Stores and exposes metrics as a time-series database.                                  |
|                           | `loki`                                | Stores, aggregates, and enables querying of all system logs.                           |
|                           | `grafana`                             | The primary UI for creating dashboards from Prometheus, Loki, and Jaeger data.       |
| **Infrastructure** | `chrony`                              | Provides Network Time Protocol (NTP) to ensure synchronised time across all services. |

-----

## Getting Started

To get a local copy up and running, follow these simple steps.

### Prerequisites

  - Docker
  - Docker Compose

### Installation

1.  **Clone the Repository**

    ```bash
    git clone https://github.com/tr8craft/system-under-test.git
    cd system-under-test
    ```

2.  **Configure Environment**
    Create a `.env` file for your local configuration. You can start by copying the example.

    ```bash
    cp .env.example .env
    ```

    Review the `.env` file and adjust any ports if they conflict with other services running on your machine.

3.  **Launch the Stack**
    The services are organised into profiles (`core` and `development`). You can launch all services using:

    ```bash
    docker compose --profile core --profile development up -d
    ```

    To shut down the stack, run:

    ```bash
    docker compose down
    ```

4.  **Accessing Services**
    Once the containers are running, you can access the UIs in your browser:

      - **Grafana**: `http://localhost:3000`
      - **Jaeger UI**: `http://localhost:16686`
      - **Kafdrop**: `http://localhost:9000`
      - **Keycloak**: `http://localhost:8080`

-----

## Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

Please read our `CONTRIBUTING.md` for details on our code of conduct and the process for submitting pull requests to us. Key requirements include:

1.  **Conventional Commits**: All commit messages must adhere to the [Conventional Commits specification](https://www.conventionalcommits.org/en/v1.0.0/).
2.  **[Developer Certificate of Origin (DCO)](https://developercertificate.org/)**: You must sign off on your commits to certify that you have the right to contribute them. This is done by adding a `Signed-off-by` line to your commit messages.
    ```bash
    git commit -s -m "feat(<scope>): create a new feature"
    ```

-----

## License

This repository is dual-licensed to separate code from documentation.

  - All code is licensed under the [Apache License 2.0](https://www.google.com/search?q=LICENSE).
  - All documentation, including this `README.md`, is licensed under the [Creative Commons Attribution 4.0 International License](https://creativecommons.org/licenses/by/4.0/).
  - The project additionally adheres to the full [Hippocratic License 3.0](https://firstdonoharm.dev/version/3/0/full.html).
