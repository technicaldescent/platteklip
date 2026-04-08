# SPDX-FileCopyrightText: 2026 technical descent
# SPDX-License-Identifier: CC-BY-4.0

@PK-DC-02
Feature: SRS-DC02 - ECDSA P-384 certificate key pairs
  As a Platform Engineer
  I want all certificates to use ECDSA with the P-384
  curve
  So that key material uses a single, strong algorithm
  across the platform

  @PK-DC-02.01
  Scenario: Deployment script generates ECDSA P-384 keys
    Given the deploy.sh script is loaded
    When the certificate generation commands are inspected
    Then every openssl ecparam or openssl genpkey command MUST specify secp384r1
    And no RSA key generation commands MUST be present
