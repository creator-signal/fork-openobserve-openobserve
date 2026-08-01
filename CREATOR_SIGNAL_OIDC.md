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
the OSS build. Keep the required ZITADEL role narrow and use ingestion tokens, not interactive OIDC
sessions, for collectors.

Existing native-login users cannot be silently linked. The first successful login records both
email-to-subject and subject-to-email bindings, so subsequent logins are bound to `(issuer, sub)`
rather than trusting a reissued email address.

## Build

```bash
cargo build --profile release-prod --features oidc,mimalloc
docker build -f deploy/build/Dockerfile.oidc .
```

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

`ZO_OIDC_CLIENT_SECRET` is also supported, but production should mount a read-only secret file.
Set only one secret source. HTTP issuer, redirect, and post-login URLs are rejected unless
`ZO_OIDC_INSECURE_ALLOW_HTTP=true`; that exception is intended only for isolated local testing.

Configure the ZITADEL web application with the exact redirect URI, Authorization Code + PKCE,
project role assertion/check enabled, verified email claims, and the `platform:operator` project
role. Keep the native root login enabled until OIDC and rollback have been accepted live.

## Upstream and release model

`.creator-signal/openobserve-base.json` records the exact upstream `main` commit from which the
overlay branch was created. The upstream watcher opens a PR whenever upstream `main` advances.
Nightly compatibility CI performs a throw-away merge with upstream `main` to reveal refactor
conflicts before the next update.

Release tags include the recorded upstream commit prefix, for example:

```bash
git tag -a openobserve-main-72f7bff3787e-cs.1 -m "OpenObserve main 72f7bff3787e with Creator Signal OIDC cs.1"
git push origin openobserve-main-72f7bff3787e-cs.1
```

The release workflow refuses a tag whose upstream commit differs from the marker file or whose
commit does not descend from that exact upstream commit. It publishes a Linux AMD64 GHCR
image, keyless signature, registry provenance, SPDX SBOM, checksums, source archive, and validated
`release-metadata.json`. The stack should consume the image by digest from that metadata, never by
`latest`.

Repository CI does not prove live acceptance. Before promotion, separately verify TLS and callback
URLs, secure cookies, allowed and denied ZITADEL roles, restart persistence, ingestion/query,
backup/restore, and rollback to the previous image digest.
