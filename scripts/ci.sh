#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

# =================================================================
# scripts/ci.sh — attested CI pipeline
# =================================================================
#
# Wraps each Dagger stage with ``witness run`` to produce
# in-toto attestations signed via Sigstore keyless (OIDC).
#
# Usage:
#
#   ./scripts/ci.sh
#
# Prerequisites:
#
#   - dagger, witness on PATH
#   - Sigstore OIDC (opens browser on first attestation)
#
# Attestations are written to
# gemara/evidence/attestations/ and can be verified
# against the Witness policy with:
#
#   witness verify \
#       --policy witness/policy-signed.json \
#       --attestations gemara/evidence/attestations/
#
# This script is VCS-independent.  It runs identically
# on any POSIX system regardless of the hosting platform.

set -euo pipefail

# -----------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------

ATTESTATION_DIR="gemara/evidence/attestations"

WITNESS_COMMON=(
    --signer-fulcio-url "https://fulcio.sigstore.dev"
    --signer-fulcio-oidc-client-id "sigstore"
    --signer-fulcio-oidc-issuer "https://oauth2.sigstore.dev/auth"
    --timestamp-servers "https://freetsa.org/tsr"
    --attestations "git"
    --attestations "environment"
)

mkdir -p "${ATTESTATION_DIR}"

# -----------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------

_step() {
    local step_name="$1"
    shift
    local outfile="${ATTESTATION_DIR}/${step_name}.json"

    echo ""
    echo "=== ${step_name} ==="

    witness run \
        --step "${step_name}" \
        --outfile "${outfile}" \
        "${WITNESS_COMMON[@]}" \
        -- "$@"

    echo "--- attestation: ${outfile}"
}

# -----------------------------------------------------------------
# Pipeline stages
# -----------------------------------------------------------------

_step test-unit \
    dagger call test-unit --source=.

_step quality \
    dagger call quality --source=.

_step acceptance \
    dagger call acceptance --source=.

_step policy \
    dagger call policy --source=.

# -----------------------------------------------------------------
# Summary
# -----------------------------------------------------------------

echo ""
echo "=== pipeline complete ==="
echo "Attestations: ${ATTESTATION_DIR}/"
ls -1 "${ATTESTATION_DIR}"/*.json 2>/dev/null || true
