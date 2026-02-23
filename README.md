<!--
# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: CC-BY-4.0
-->

# Platteklip

**Zero-Trust Telemetry Gateway and Observability Plane**

## Table of Contents

- [About The Project](#about-the-project)
- [Compliance & Standards](#compliance--standards)
- [System Architecture](#system-architecture)
- [Getting Started](#getting-started)
- [Development & Contributing](#development--contributing)
- [License](#license)

---

## About the Project

Platteklip provides a blueprint for building a secure and observable system for complex Data Engineering, DevSecOps, and SCADA environments. It integrates a telemetry pipeline based on **OpenTelemetry** with event-driven messaging systems like **Kafka** and **MQTT**.

The primary goals are:

- **To provide a reference implementation** for monitoring complex, distributed applications using open standards.
- **To enforce zero-trust security** through strict policy management, identity verification, and container hardening.
- **To bridge infrastructure and machine learning workflows** securely.

---

## Compliance and Standards

This project adheres to industry standards to guarantee software supply chain integrity and operational security:

- **NIST 800-53 Rev 5:** Implementing controls for Developer Security Testing (SA-11), Least Functionality (CM-7), and Vulnerability Scanning (RA-5).
- **ISO/IEC 27002:2022:** Adhering to secure development life cycles (8.25), secure coding practices (8.28), and strict access control parameters.
- **Scientific Python SPEC 0:** Guaranteeing predictable deprecation cycles for core machine learning and data dependencies.
- **Software Supply Chain Security:** All builds produce SPDX 3 compliant Software Bills of Materials (SBOMs) and are cryptographically signed via Sigstore.

---

## System Architecture

The architecture is built around decoupled, asynchronous communication and strict policy enforcement:

- **Identity and Policy:** Managed by Keycloak (Identity) and Open Policy Agent / OPA (Authorization).
- **Observability Stack:** Metrics, logs, and distributed traces are collected via the OpenTelemetry Collector and routed to Prometheus, Loki, and Jaeger.
- **Event Streaming:** Apache Kafka serves as the durable, high-throughput message bus, with MQTT (Mosquitto) handling edge and SCADA telemetry.
- **Machine Learning Integrations:** PyTorch, ONNX, and Safetensors, tracked via Data Version Control (DVC) and MLCroissant.

---

## Getting Started

To get a local development environment running, ensure you have **Docker**, **Docker Compose**, and **Python 3.14+** installed.

### Installation

1. **Clone the Repository**
   ```bash
   git clone [https://github.com/technicaldescent/platteklip.git](https://github.com/technicaldescent/platteklip.git)
   cd platteklip

```

2. **Configure Environment**
Create a `.env` file for local configuration.
```bash
cp .env.example .env

```

Review the `.env` file and adjust any ports if they conflict with your host machine.

3. **Launch the Services**
Platteklip uses modular Docker Compose files. Launch the development and infrastructure services using modern Docker compose syntax:
```bash
docker-compose -f compose.yaml -f compose.development.yaml up -d

```

To cleanly shut down the stack, run:
```bash
docker-compose down

```

4. **Accessing Services**
* **Grafana (Dashboards):** `http://localhost:3000`
* **Jaeger (Traces):** `http://localhost:16686`
* **Keycloak (Identity):** `http://localhost:8080`

---

## Development and Contributing

### Tooling and Continuous Integration

Platteklip uses **Hatch** as its build system and environment manager. Our CI pipeline enforces a rigorous standard of quality:

* **Quality Checks:** Code must pass Black formatting, strict MyPy type checking, and Bandit/Safety vulnerability scans. Run checks locally:
```bash
hatch run quality:check

```

* **Testing Coverage:** We enforce a strict 100% test coverage requirement and a maximum cyclomatic complexity of 10. Run tests via:
```bash
hatch run audit:run mode=safety

```

### Commit Standards

1. **Conventional Commits:** All commit messages MUST adhere to the [Conventional Commits v1.0.0 specification](https://www.conventionalcommits.org/en/v1.0.0/). This triggers our automated semantic versioning and changelog generation.
2. **Developer Certificate of Origin (DCO):** You must sign off on your commits to certify you have the right to contribute them using the `-s` flag:
```bash
git commit -s -m "feat(telemetry): add new OTel processor"

```

---

## License

This repository uses distinct licensing to separate concerns:

* All source code is licensed under the **[Apache License 2.0](https://www.google.com/search?q=LICENSES/Apache-2.0.txt)**.
* All documentation (including this file) is licensed under the **[Creative Commons Attribution 4.0 International License](https://www.google.com/search?q=LICENSES/CC-BY-4.0.txt)**.
* Adhere to the **REUSE Specification** for clear, machine-readable metadata.
