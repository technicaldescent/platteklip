# SPDX-FileCopyrightText: 2026 technical descent
# SPDX-License-Identifier: CC-BY-4.0

Feature: SyRS-SEC - Loki Security Posture
  As a Security Architect
  I want the log aggregation system to mandate secure data in transit and secret isolation
  So that unauthorized clients are blocked and cryptographic material is protected

  Scenario: The system rejects unauthenticated client traffic
    Given a proposed Loki deployment configuration
    And the configuration lacks mutual TLS client verification
    When the system compliance check is executed
    Then the deployment configuration is rejected

  Scenario: The system enforces secure cryptographic mounting
    Given a proposed Loki deployment configuration
    And the configuration mounts certificates from a secure memory partition
    When the system compliance check is executed
    Then the deployment configuration is accepted
