# SPDX-FileCopyrightText: 2026 technical descent
# SPDX-License-Identifier: CC-BY-4.0

@PK-RA-03
Feature: SRS-RA03 - Volume UID alignment
  As a Platform Engineer
  I want volume UIDs in .env to match the container
  image user
  So that services can write to mounted volumes after
  recreation

  Background:
    Given the .env configuration is loaded

  @PK-RA-03.01
  Scenario: Prometheus UID matches distroless image
    When the UID_PROMETHEUS value is inspected
    Then UID_PROMETHEUS MUST be "65532"

  @PK-RA-03.02
  Scenario: Every UID variable is documented
    When each UID_* variable is inspected
    Then every UID_* variable MUST have a comment documenting the source
