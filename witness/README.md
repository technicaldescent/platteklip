<!--
SPDX-FileCopyrightText: 2025 technical descent
SPDX-License-Identifier: CC-BY-4.0
-->

# Witness attestation

This directory contains the Witness policy and setup
instructions for SLSA Level 4 build provenance.

## Architecture

```
scripts/ci.sh                   scripts/release.sh
     │                                │
     ├─ witness run --step test-unit  ├─ witness run --step build
     │    └─ dagger call test-unit    │    └─ dagger call build
     ├─ witness run --step quality    ├─ witness run --step sbom
     │    └─ dagger call quality      │    └─ dagger call sbom
     ├─ witness run --step acceptance ├─ witness run --step publish
     │    └─ dagger call acceptance   │    └─ dagger call publish
     ├─ witness run --step policy     ├─ witness verify (gate)
     │    └─ dagger call policy       ├─ cosign sign
     │                                └─ cosign attest (SBOM)
     ▼                                     ▼
  attestations/                      signed image in GHCR
```

Witness wraps each Dagger call from outside the
container.  Dagger provides hermeticity (isolated
builds).  Witness provides provenance (who ran what,
when, on which commit).  Sigstore provides identity
binding (OIDC, not keys).

## Prerequisites

```
brew install witness cosign
```

Or install from source:

```
bash <(curl -s https://raw.githubusercontent.com/in-toto/witness/main/install-witness.sh)
```

## Initial setup

### 1. Download the Fulcio root certificate

```
curl -s https://fulcio.sigstore.dev/api/v2/trustBundle \
    | jq -r '.chains[0].certificates[0]' \
    > witness/fulcio-root.pem
```

### 2. Populate the policy

Base64-encode the root certificate and paste it into
`witness/policy.json` at `roots.fulcio.certificate`:

```
base64 -i witness/fulcio-root.pem
```

### 3. Sign the policy

```
witness sign \
    --signer-fulcio-url https://fulcio.sigstore.dev \
    --signer-fulcio-oidc-client-id sigstore \
    --signer-fulcio-oidc-issuer https://oauth2.sigstore.dev/auth \
    -f witness/policy.json \
    -o witness/policy-signed.json
```

Commit `policy-signed.json`.  The unsigned
`policy.json` is the editable source.

## Workflow

### Development (every push)

```
./scripts/ci.sh
```

Runs test-unit, quality, acceptance, policy.  Each
produces a signed attestation in
`gemara/evidence/attestations/`.

### Release

```
semantic-release version           # signed tag
./scripts/ci.sh                    # attested pipeline
./scripts/release.sh               # build, publish, sign
git push --follow-tags             # push tag and code
```

`release.sh` reads the version from the git tag
created by `semantic-release`.  It checks that all
CI attestations exist before proceeding to build,
SBOM, publish, and cosign signing.

## Adding a new pipeline stage

1. Add the Dagger function in `.dagger/src/ci/__init__.py`
2. Add a `_step` call in the appropriate script
3. Add the step to `witness/policy.json`
4. Re-sign the policy

## CI integration

Any CI platform calls the same scripts:

```yaml
# GitHub Actions
- run: ./scripts/ci.sh

# GitLab CI
script:
  - ./scripts/ci.sh

# Codeberg / Woodpecker
commands:
  - ./scripts/ci.sh
```

For releases, the CI job calls `semantic-release
version` then `./scripts/release.sh`.  The OIDC
identity token is provided by the platform.

## Rego policies

The Witness policy supports embedded OPA Rego rules
per step.  These are added after the first attested
run, written against the actual attestation
structure.  See `witness/policy.json` for the step
definitions where Rego rules are attached.

## Verification

```
cosign verify \
    --certificate-identity=raymond.ellis@gmail.com \
    --certificate-oidc-issuer=https://oauth2.sigstore.dev/auth \
    ghcr.io/technicaldescent/mqtt-producer:0.3.0

cosign verify-attestation \
    --type spdxjson \
    --certificate-identity=raymond.ellis@gmail.com \
    --certificate-oidc-issuer=https://oauth2.sigstore.dev/auth \
    ghcr.io/technicaldescent/mqtt-producer:0.3.0
```
