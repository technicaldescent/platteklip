# SPDX-FileCopyrightText: 2026 technical descent
# SPDX-License-Identifier: CC-BY-4.0

Feature: SRS-VAL - Loki mTLS Policy Validation
  As a Platform Engineer
  I want the OPA policy engine to explicitly validate the http_tls_config properties
  So that the SyRS security posture is programmatically enforced

  Background:
    Given a baseline valid Loki JSON configuration
    And the OPA policy engine is loaded with "services/loki/policy.rego"

  Scenario: Policy enforces RequireAndVerifyClientCert
    Given the configuration property "server.http_tls_config.client_auth_type" is set to "VerifyIfGiven"
    When the policy is evaluated against the configuration
    Then the evaluation result should be "deny"
    And the policy violation message should contain "must be RequireAndVerifyClientCert"

  Scenario: Policy enforces secure secret paths
    Given the configuration property "server.http_tls_config.key_file" is set to "/etc/ssl/loki.key"
    When the policy is evaluated against the configuration
    Then the evaluation result should be "deny"
    And the policy violation message should contain "must start with \"/run/secrets/\""
