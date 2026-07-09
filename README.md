# Z-Arch Extension: kms-bootstrap

`kms-bootstrap` bootstraps Cloud KMS for envelope-encryption workloads.

## What It Does
- Enables `cloudkms.googleapis.com` (optional, enabled by default).
- Ensures a key ring exists in the configured location.
- Ensures a crypto key exists in that key ring.
- Validates immutable crypto-key shape (location path and purpose).
- Optionally enforces key rotation period in days.
- Is idempotent for already-compliant resources.

## zarch.yaml Example
```yaml
extensions:
  kms-bootstrap:
    type: "kms-bootstrap"
    required_roles:
      - "roles/cloudkms.admin"
      - "roles/serviceusage.serviceUsageAdmin"
    config:
      location: "example-region1"
      key_ring: "app-keyring"
      key_id: "app-dek-wrapper"
      purpose: "ENCRYPT_DECRYPT"
      rotation_period_days: 90
      enable_api: true
      preflight_only: false
      retry_attempts: 3
      retry_initial_delay_seconds: 1.0
      retry_backoff_multiplier: 2.0
```

## Hooks
- `async post_project_bootstrap`

## Config Reference
| Key | Type | Default | Notes |
|---|---|---|---|
| `location` | string | project region | KMS location for key ring and crypto key. |
| `key_ring` | string | none | Required key ring ID. |
| `key_id` | string | none | Required crypto key ID. |
| `purpose` | string | `ENCRYPT_DECRYPT` | Canonical value is `ENCRYPT_DECRYPT`; `ENCRYPTION` is accepted as an alias for compatibility. |
| `rotation_period_days` | integer/null | `null` | Optional positive day count for automatic key rotation. |
| `enable_api` | boolean | `true` | When true, extension enables `cloudkms.googleapis.com`. |
| `preflight_only` | boolean | `false` | When true, performs validation only and refuses all mutations (create/update/enable). |
| `retry_attempts` | integer | `3` | Maximum attempts for transient gcloud failures. Must be positive. |
| `retry_initial_delay_seconds` | float | `1.0` | Initial retry delay. Set `0` to disable sleep between retries. |
| `retry_backoff_multiplier` | float | `2.0` | Delay multiplier after each retry. Must be `>= 1`. |

## Idempotency Guarantees
- Safe to run repeatedly.
- Existing matching key ring/key are reused.
- Rotation updates run only when configured and drift is detected.
- Transient gcloud failures are retried with configurable backoff.

## Failure Behavior
- Fails fast when existing key ring/key shape conflicts with config.
- Fails when required fields are missing or invalid.
- Fails when required IAM permissions are missing.
- In `preflight_only` mode, fails on any detected drift or missing resources without mutating infrastructure.

## Non-Goals
- No IAM binding management.
- No runtime environment-variable mutation.
- No Secret Manager key material bootstrap.

## Install (MCP workflow)
Use MCP `install_extension` after the extension block is present in `zarch.yaml`.
