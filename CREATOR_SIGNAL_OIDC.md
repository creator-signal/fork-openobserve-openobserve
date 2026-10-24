# OpenObserve OSS OIDC overlay

This fork adds authentication and admission to the AGPL OpenObserve build without enabling or
copying the private enterprise crates. It is intentionally a thin overlay on an exact upstream
`main` commit so upstream updates can be merged and tested independently.

## Security and authorization boundary

The `oidc` feature implements Authorization Code with PKCE, browser-bound one-time state, nonce
validation, RS256/JWKS signature verification, exact issuer and audience checks, verified-email
enforcement, and mandatory required-role admission. Browser authentication uses an opaque,
persisted server-side session; provider access and refresh tokens are not accepted as OpenObserve
API credentials.

OIDC is authentication and fixed-organization admission, not enterprise RBAC. Admitted users are
OpenObserve `Admin` users in `ZO_OIDC_DEFAULT_ORG`, matching the authorization model available in
the OSS build. Keep the required ZITADEL role narrow. The Creator Signal build additionally exposes
three fixed automation identities when explicitly enabled: OTLP ingestion only,
bounded governed aggregate queries only, and governed dashboard reconciliation only. These are not
general OSS users and cannot use interactive sessions, user administration, raw search, dashboard
deletion, or a different organization.

Existing native-login users cannot be silently linked. The first successful login records both
email-to-subject and subject-to-email bindings, so subsequent logins are bound to `(issuer, sub)`
rather than trusting a reissued email address.

## Build

```bash
cargo build --profile release-prod --features oidc,mimalloc
docker build -f deploy/build/Dockerfile.oidc .
```

The OIDC Dockerfile consumes digest-pinned official Node, Rust and Debian bases
directly from Docker Hub. Its existing builder stage installs the same pinned
`nightly-2026-05-20` toolchain and native build dependencies; no separately
published builder image or ECR credentials are required. Cargo builds remain
locked to the reviewed dependency graph. This removes the public ECR anonymous
data-quota dependency without changing the registered release workflow or gates.

Builds without `--features oidc` retain upstream OSS login behavior and do not expose the OIDC
routes.

## Runtime configuration

Required production settings:

```dotenv
ZO_OIDC_ENABLED=true
ZO_OIDC_ISSUER=https://auth.creatorsignal.com
ZO_OIDC_CLIENT_ID=<zitadel application client id>
ZO_OIDC_CLIENT_SECRET_FILE=/run/secrets/openobserve-oidc-client-secret
ZO_OIDC_TOKEN_ENDPOINT_AUTH_METHOD=client_secret_basic
ZO_OIDC_REDIRECT_URL=https://observe.creatorsignal.me/config/oidc/callback
ZO_OIDC_POST_LOGIN_URL=https://observe.creatorsignal.me/web/cb
ZO_OIDC_DEFAULT_ORG=creator_signal
ZO_OIDC_ROLE_CLAIM=urn:zitadel:iam:org:project:roles
ZO_OIDC_REQUIRED_ROLE=platform:operator
ZO_OIDC_SCOPES=openid profile email
ZO_OIDC_NATIVE_LOGIN_ENABLED=true
ZO_OIDC_SESSION_MAX_AGE=28800
ZO_COOKIE_SECURE_ONLY=true
ZO_COOKIE_SAME_SITE_LAX=true
ZO_WEB_URL=https://observe.creatorsignal.me
```

`ZO_OIDC_CLIENT_SECRET` is also supported in legacy mode. The direct OpenBao mode below replaces
runtime credential environment variables and files with private process memory.
Set only one secret source. HTTP issuer, redirect, and post-login URLs are rejected unless
`ZO_OIDC_INSECURE_ALLOW_HTTP=true`; that exception is intended only for isolated local testing.

Scoped automation is disabled by default. When enabled, all six settings below are required and
fail closed. Credential files must be distinct, contain 32-256 non-whitespace characters, and live
under `/run/secrets` or `/run/creator-signal-secrets`. The bounded policy is repository-owned and
limits the exact query templates, time range, result size, dashboard titles, and dashboard request
digests accepted by the middleware.

```dotenv
ZO_OIDC_AUTOMATION_ENABLED=true
ZO_OIDC_AUTOMATION_ORG=default
ZO_OIDC_AUTOMATION_INGEST_TOKEN_FILE=/run/secrets/openobserve-automation-ingest-token
ZO_OIDC_AUTOMATION_QUERY_TOKEN_FILE=/run/secrets/openobserve-automation-query-token
ZO_OIDC_AUTOMATION_DASHBOARD_TOKEN_FILE=/run/secrets/openobserve-automation-dashboard-token
ZO_OIDC_AUTOMATION_POLICY_FILE=/run/creator-signal/repository-configs/openobserve/automation-policy.json
```

Configure the ZITADEL web application with the exact redirect URI, Authorization Code + PKCE,
project role assertion/check enabled, verified email claims, and the `platform:operator` project
role. Keep the native root login enabled until OIDC and rollback have been accepted live.

## Upstream and release model

`.creator-signal/openobserve-base.json` records the exact upstream `main` commit from which the
overlay branch was created. The upstream watcher opens a PR whenever upstream `main` advances.
Nightly compatibility CI performs a throw-away merge with upstream `main` to reveal refactor
conflicts before the next update.

`creator-signal/main` is the downstream release source, initialized from fork commit
`f39daba4c30bbed820a9ffd6ead74f1a5710df7c`. This includes the OIDC implementation, scoped automation,
and subsequent public-runner changes, including the history of `creator-signal/oidc-main`.
The historical `main` branch is unchanged. Downstream changes use Issues and PRs into
`creator-signal/main`; new downstream changes must not target the upstream mirror.

After separately authorizing publication, run the existing `release-oidc.yml` workflow's
`qualify-and-publish` operation from `creator-signal/main`, supplying a new tag such as
`openobserve-main-72f7bff3787e-cs.4` (only if still unused). Do not create or push tags manually. The workflow requires the
exact current release tip and successful push CI and security audit for that revision. It reserves the immutable tag
before registry writes and creates the release after building the artifacts. A matching completed release is a no-op; partial publication
requires reviewed forward recovery. Never overwrite a partial release to make a retry pass.

Publication run [40070568007](https://github.com/creator-signal/fork-openobserve-openobserve/actions/runs/40070568007)
reserved `openobserve-main-72f7bff3787e-cs.3` at source
`31ef1034e1818016c88c126214a8b8b82a310386`, then failed before either image was pushed.
Preserve that tag as an incomplete attempt. Issue #13 repairs the missing standard protobuf
include definitions by installing `libprotobuf-dev` explicitly. The existing container check
now compiles a message importing both `google.protobuf.Duration` and `google.protobuf.Timestamp`,
rather than relying only on `protoc --version`. Retry through the same registered workflow
with a fresh tag only after the reviewed repair and exact release-tip CI/audit pass.

The release workflow refuses a tag whose upstream commit differs from the marker file or whose
commit does not descend from that exact upstream commit. It publishes a Linux AMD64 GHCR
application image and collector image, keyless signatures, registry provenance, SPDX SBOMs, checksums, source archive, and validated
`release-metadata.json`. The stack should consume the image by digest from that metadata, never by
`latest`.

Scheduled workflows are evaluated from GitHub's default branch. This change updates their source
selection to `creator-signal/main` but does not change repository settings or activate schedules
from the historical default branch. That activation is a separate governed operation.

## Direct OpenBao credentials

API delivery is opt-in; legacy file mode remains available for rollback. Both executables use
OpenBao certificate authentication over verified HTTPS. Neither writes fetched values or the
resulting session token to files, environment variables, or command arguments. The existing
certificate, private key and CA remain bootstrap inputs: this does not eliminate bootstrap key
custody, database contents, backups, swap or core-dump considerations. Do not enable credential
logging or process dumps when adopting the images.

For the application, configure only nonsecret locators:

```dotenv
ZO_OPENBAO_ENABLED=true
ZO_OPENBAO_ADDRESS=https://bao.example.test
ZO_OPENBAO_CERT_ROLE=openobserve
ZO_OPENBAO_CA_FILE=/run/bootstrap/ca.pem
ZO_OPENBAO_CERT_FILE=/run/bootstrap/client.pem
ZO_OPENBAO_KEY_FILE=/run/bootstrap/client-key.pem
ZO_OPENBAO_RUNTIME_PATH=kv/data/example/openobserve/runtime
ZO_OPENBAO_OIDC_PATH=kv/data/example/openobserve/oidc
ZO_OPENBAO_STORAGE_PATH=kv/data/example/openobserve/storage
ZO_OPENBAO_REFRESH_SECS=60
ZO_OPENBAO_MAX_STALENESS_SECS=300
```

These are examples, not production paths or newly authorized identities. The existing governed
certificate producer owns renewal and atomic replacement. Configure its role to read only the
three selected KV v2 records, renew its own bounded token and revoke it on exit. No root OpenBao token is needed.

Every `ZO_OPENBAO_*` setting is listed above: `ENABLED` selects API mode (default false);
`ADDRESS` is an HTTPS origin; `CERT_ROLE` is the exact certificate-role name; `CA_FILE`,
`CERT_FILE` and `KEY_FILE` are absolute bootstrap file paths; `RUNTIME_PATH`, `OIDC_PATH`
and `STORAGE_PATH` are exact KV v2 **data API** paths. The two optional duration settings
are seconds: refresh defaults to 60 (allowed 5–300), maximum staleness defaults to 300
(at least refresh and at most 900). Staleness is independent of the authentication token TTL.
Restart to change provider settings; replacing the certificate/key pair is picked up at refresh.

Use distinct application and collector certificates with pinned `allowed_common_names` and
distinct exact role names (`openobserve` and `observe-collector` in these examples). Proposed
role lifetimes are `token_ttl=1h`, `token_max_ttl=4h`; neither has been set or verified on a live
role by this PR. Confirm the actual source addresses seen by OpenBao before setting
`token_bound_cidrs`; do not copy guessed host/container CIDRs. Ensure the default policy adds
no broader permissions (use `token_no_default_policy=true` with the explicit self operations).
These are consumer-automation prerequisites, not provisioning instructions or deployment authority.

The application's example policy is exactly:

```hcl
path "kv/data/example/openobserve/runtime" { capabilities = ["read"] }
path "kv/data/example/openobserve/oidc" { capabilities = ["read"] }
path "kv/data/example/openobserve/storage" { capabilities = ["read"] }
path "auth/token/renew-self" { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
```

The collector's separate policy is exactly:

```hcl
path "kv/data/observability/collector" { capabilities = ["read"] }
path "auth/token/renew-self" { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
```

Substitute only the governed deployment's exact data paths. Neither role needs `list`,
`/metadata/` access, wildcard data access, other workloads' identities or policy-management access.

| Record | Required string fields |
| --- | --- |
| runtime | `root_email`, `root_password`, `automation_ingest_token`, `automation_query_token`, `automation_dashboard_token` |
| oidc | `client_id`, `client_secret` |
| storage | `access_key`, `secret_key` |

Remove legacy credential variables and secret-file selectors when enabling API delivery; mixed
sources fail closed. Keep the OIDC issuer, redirect, organization, role, automation policy file and
capability settings. The policy file is nonsecret repository configuration. Only the default
AWS/S3/MinIO storage account is supported in API mode. Other storage providers and multiple
accounts require a separate implementation before adoption.

The application authenticates and validates all records before starting its consumers. It
publishes a complete snapshot, refreshes every minute, reuses/renews its session, retries a revoked
session once, and re-reads the certificate pair on refresh. Existing credentials remain usable for
at most five minutes after the last complete fetch. Beyond that, credential consumers fail and
health GET/HEAD return 503. Cold start without valid credentials fails. Response bodies are bounded
to 64 KiB, redirects are denied and errors omit upstream payloads.

Both providers renew/re-authenticate at approximately two-thirds of the returned token TTL,
independently of the data-poll timer. Every data read validates the KV v2 version metadata;
version changes count rotations, and even unchanged successful reads refresh the freshness
deadline. Snapshot replacement still requires the complete valid record set. Poll failures retain
the last good snapshot only within the configured freshness window and retry with exponential
backoff and jitter: initially 5–10 seconds, capped at 150–300 seconds. Auth-failure signals
cannot bypass an outage retry deadline and are debounced for five seconds.

At the S3 HTTP response boundary, 401 and recognized credential-related 403 error codes
(`InvalidAccessKeyId`, `SignatureDoesNotMatch`, `ExpiredToken`, `InvalidToken`,
`TokenRefreshRequired`) schedule refresh. Generic S3 `AccessDenied` does not. The observer
examines at most 64 KiB while forwarding original response frames unchanged. At the OIDC
client-authenticated token endpoint, 401/403 schedule refresh; discovery/userinfo failures do
not. These hooks never replay an S3 operation or authorization code. Collector ingestion 401/403
also schedules refresh and returns the original response. Existing exporter retries remain its
own explicitly configured policy.

Application `/metrics` exports `zo_openbao_last_success_timestamp_seconds`,
`zo_openbao_consecutive_failures`, `zo_openbao_refresh_failures_total`,
`zo_openbao_auth_refreshes_total`, `zo_openbao_rotations_total`,
`zo_openbao_snapshot_age_seconds` and `zo_openbao_ready` without secret/path/role labels.
The collector registers equivalent OpenTelemetry instruments under the `openbao_` prefix
(observable counters omit `_total` in their instrument names). Its telemetry reader/exporter
configuration determines exposure. These report successful fetch time, current age/readiness,
consecutive failures and cumulative failures/signals/version changes. No upstream bodies or
credential values enter lifecycle telemetry.

Graceful shutdown stops refresh, immediately denies credential consumption, attempts
`auth/token/revoke-self` within a five-second bound and clears the retained snapshot/session.
It reuses the most recent successfully verified TLS transport, including a replacement
certificate used by data polling before the next token renewal; no bootstrap file I/O is needed.
Failure is reported with a generic status; abrupt kills cannot revoke and rely on the bounded
OpenBao token lifetime. The collector uses the earlier of its shutdown context and five seconds.

Automation checks, OIDC exchanges and S3 request signing read the current snapshot. Root credentials
follow the existing database bootstrap behavior: the first database initialization uses the fetched
root identity; fetching a different root value does not rotate an existing database user. Root
rotation requires its own governed database operation. Root passwords and provider snapshots are
excluded from configuration serialization/debug formatting.

## Collector memory delivery

`collector/builder-config.yaml` builds the pinned OpenTelemetry v0.157.0 distribution with the
`openbaoauth` HTTP exporter extension. `collector/config.example.yaml` shows nonsecret configuration.
The collector requires a **separate narrow certificate role and record**; do not give it the
application's runtime, OIDC or object-storage records. Its exact KV v2 record path must end in
`/collector` and contain only two fields:

- `schema`: `creator-signal.openobserve-collector/v1`
- `automation_ingest_token`: the same ingestion credential accepted by the application

Provisioning that identity, record projection and production configuration belongs to the private
consumer's governed automation. This PR provisions none of them. Existing broad records are
deliberately rejected. Only the configured HTTPS origin and exact POST `v1/logs`, `v1/metrics` and
`v1/traces` exporter paths receive authentication. Other destinations, query strings, redirects
and administration endpoints cannot obtain the credential. This implements OTLP HTTP, not gRPC.
Refresh, bounded outage, certificate re-read and restart reconstruction match the application
model. An expired collector snapshot rejects export; normal exporter retry/queue settings still
govern data retention. The example is minimal: preserve the owning deployment's privacy filtering,
resource processing, network exposure and queue policy when adopting it.

The image enables `extension.healthcheck.useComponentStatus` and includes a silent
`/collector-healthcheck` probe for the loopback HTTP readiness endpoint (port 13133).
Use the example's v2 `health_check` configuration, including recoverable errors with
`recovery_duration: 0s`: an expired snapshot reports a fixed recoverable status and
HTTP 503; a successful refresh restores HTTP 200. Status is checked once per second
independently of refresh backoff, and only transitions are reported. The probe accepts
only an optional numeric `--port`, ignores proxies, rejects redirects, never reads or
prints response bodies and times out after two seconds. Docker checks execute this
probe, not config validation. When running the distribution outside the image, pass
`--feature-gates=+extension.healthcheck.useComponentStatus` explicitly. The running
distribution acceptance test exercises healthy, stale and recovered probe results.

## Source validation and adoption boundary

Issue #7 also updates inherited security dependencies: VRL 0.33.1 / domain 0.12.3,
ZIP 9.0.5, rustls 0.23.46, rustls-webpki 0.103.16, quinn-proto 0.11.19 and
webpki trust roots 1.0.11. The small Vector enrichment/category dependencies are
maintained in `vendor/` with pinned upstream provenance and MPL-2.0 licences so
all application and enrichment paths share the patched VRL types. Their upstream
unit tests are included in the existing CI. No audit finding is suppressed.

```bash
cargo +stable test --locked --manifest-path tests/openbao-provider/Cargo.toml --target-dir .tmp/7-openbao-memory/cargo
go run go.opentelemetry.io/collector/cmd/builder@v0.157.0 --config collector/builder-config.yaml
cd collector/openbaoauthextension
OPENBAO_COLLECTOR_BINARY="$(pwd)/../../.tmp/7-openbao-memory/collector-distribution/otelcol-contrib" go test -race -count=1 -v ./...
```

Use an absolute binary path for the last command (and `.exe` on Windows). The Rust harness includes
the actual production provider source. Tests use synthetic HTTPS servers requiring verified client
certificates; they exercise snapshot atomicity, renewal, certificate replacement, outage expiry,
scope, redaction, actual collector export, credential refresh and process restart. They do not prove
a live OpenBao policy, deployed certificate producer or production OpenObserve runtime. The existing
CI additionally compiles OSS/OIDC and runs the OIDC/automation authorization tests.
Lifecycle cases also cover debounced consumer-triggered refresh without replay, classified S3
denials, jitter/backoff bounds, exported metric values, version changes and idempotent revocation.

Source merge does not publish images or deploy services. Before private consumer adoption, separately
publish and verify both immutable image digests and provenance, implement the narrow collector
record/identity through its owning automation, validate both production-shaped consumers, and obtain
deployment authorization. Preserve legacy files until a shadow byte comparison, governed consumer
switch/restart and recovery acceptance prove retirement is safe. Equal bytes establish duplication,
not staleness. No host file deletion or restart is part of this source change.

Repository CI does not prove live acceptance. Before promotion, separately verify TLS and callback
URLs, secure cookies, allowed and denied ZITADEL roles, restart persistence, ingestion/query,
backup/restore, and rollback to the previous image digest.
