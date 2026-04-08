  # SPDX-FileCopyrightText: 2025 technical descent
  # SPDX-License-Identifier: Apache-2.0

  Feature: Keycloak PostgreSQL Hardening
    Validates the PostgreSQL configuration backing
    Keycloak against CIS PostgreSQL v1.0.0 Benchmark
    and OWASP Database Security requirements.

    Background:
      Given the PostgreSQL configuration is loaded

    # CIS 5.2
    @control @PK-DC-01
    Scenario: Network binding is restricted
      Then listen_addresses must not be "*"
       And listen_addresses must not be "0.0.0.0"

    # CIS 5.6
    @control @PK-IA-01
    Scenario: SCRAM-SHA-256 authentication is enforced
      Then password_encryption must be "scram-sha-256"

    # CIS 6.9
    @control @PK-DC-01
    Scenario: TLS 1.3 is the minimum protocol version
      Then ssl_min_protocol_version must be "TLSv1.3"

    # CIS 3.1.25 + IAM
    @control @PK-UC-01
    Scenario: pgAudit logging is configured correctly
      Then pgaudit.log must be "all"
       And pgaudit.log_parameter must be "on"
       And log_statement must be "none"

    # SIEM integration
    @control @PK-UC-01
    Scenario: JSON log destination for SIEM ingestion
      Then log_destination must be "jsonlog"
