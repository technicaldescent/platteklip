# SPDX-FileCopyrightText: 2026 technical descent
# SPDX-License-Identifier: CC-BY-4.0

@PK-DC-01
Feature: SRS-DC01 - TLS 1.3 on all encrypted channels
  As a Platform Engineer
  I want every encrypted channel to use TLS 1.3
  exclusively
  So that deprecated protocol versions cannot be
  negotiated

  @PK-DC-01.01
  Scenario: nginx permits only TLS 1.3
    Given the nginx configuration is loaded
    When the ssl_protocols directive is inspected
    Then ssl_protocols MUST specify "TLSv1.3" only

  @PK-DC-01.02
  Scenario: MQTT producer constrains TLS to 1.3
    Given the MQTTConnectionConfig defaults
    When the TLS version constraints are inspected
    Then tls_min_version MUST be TLSv1.3
    And tls_max_version MUST be TLSv1.3

  @PK-DC-01.03
  Scenario: Mosquitto broker permits only TLS 1.3
    Given the mosquitto.conf configuration is loaded
    When the tls_version directive is inspected
    Then tls_version MUST be "tlsv1.3"
