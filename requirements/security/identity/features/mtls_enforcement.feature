# SPDX-FileCopyrightText: 2026 technical descent
# SPDX-License-Identifier: CC-BY-4.0

@PK-IA-01
Feature: SRS-MTLS - mTLS enforcement on all inter-service communication
  As a Platform Engineer
  I want all inter-service communication to use mutual TLS
  So that the identity and integrity of every connection
  is cryptographically verified

  Background:
    Given a baseline valid compose.yaml configuration
    And the OPA policy engine is loaded with "policy/compose.rego"

  @PK-IA-01.01
  Scenario: Every networked service presents a client certificate
    Given a compose file with services defined
    But "weaver" and "kafka" are exempt as non-networked or PKCS12 services
    When each service's secrets are inspected
    Then every service MUST have a "tls_certificate.crt" secret
    And every service MUST have a "tls_private_key.key" secret

  @PK-IA-01.02
  Scenario: Nginx verifies upstream TLS certificates
    Given the nginx default.conf configuration
    When the proxy_ssl directives are inspected
    Then proxy_ssl_verify MUST be set to "on"
    And proxy_ssl_trusted_certificate MUST reference the platform CA

  @PK-IA-01.03
  Scenario: Mosquitto requires client certificates
    Given the mosquitto.conf configuration
    When the TLS directives are inspected
    Then require_certificate MUST be set to "true"
    And use_identity_as_username MUST be set to "true"
