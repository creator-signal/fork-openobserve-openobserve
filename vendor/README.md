# Vector enrichment compatibility source

## Zstandard security compatibility (#18)

`zstd-compat` contains the checksum-verified crates.io **zstd 0.14.3** source,
including its licence and tests. `zstd-import.json` records the archive checksum
and every original file hash. Its package version is adapted to `0.13.4`
so the existing Arrow/DataFusion/Parquet/Tantivy/VRL dependency constraints can
consume the fixed implementation without importing unrelated major upgrades.
`zstd-safe-compat` similarly contains exact fixed **zstd-safe 8.2.0** source
under compatibility package version `7.2.5`; `zstd-safe-import.json` records
the verified archive and every source hash. The high-level compatibility
manifest selects that binding so existing direct `compression-codecs` callers
and high-level callers share the same types. These manifest-only adaptations
do not retain the vulnerable 7.2.4 implementation. Consumers already accepting
the 0.14/8.2 APIs continue using their unchanged registry packages.

This replaces the implementation affected by RUSTSEC-2026-0391 and removes the
old zstd-safe line affected by RUSTSEC-2026-0398/0403; it does not suppress an
advisory or add an audit exception. Native CI checks the exact imported bytes,
executes the upstream codec tests, and builds both OSS and OIDC consumers.
Retire this compatibility import when all pinned upstream consumers accept
the fixed 0.14 API directly. Preserve the source provenance and licences.

These two small MPL-2.0 crates are imported from `openobserve/vector` revision
`5b87303cb89c1279407f9b64f267ff6a546fc679`, the revision previously selected by
the application lockfile. `vector-import.json` records the original file hashes
before downstream adaptation. Both packages retain the upstream licence.

The upstream Vector workspace pins VRL 0.31, which retains the vulnerable
`domain` 0.11 DNS dependency. Keeping the small enrichment API in this workspace
allows it and OpenObserve to use the same VRL 0.33.1 types and the patched
`domain` 0.12.3 dependency. Importing the entire Vector application or carrying
two incompatible VRL versions would not solve that dependency boundary.

Downstream changes: dependency declarations resolve within this workspace;
required compiler API adaptations and formatting, if any, are reviewed in the
same PR. The application still exposes its existing enrichment functions.
The normal Rust checks and enrichment tests cover the shared type boundary.

Future refresh: compare both imported crates against the pinned upstream
revision, review any new licence/dependency changes, and update provenance and
tests together. Remove these copies when a pinned upstream dependency supports
the application's patched VRL version without retaining the old dependency.

## ZIP compatibility patches

`chromiumoxide-fetcher` is imported from the application's existing Chromiumoxide
revision `6f2392f78ae851e2acf33df8e9764cc299d837db` (MIT OR Apache-2.0).
`utoipa-swagger-ui` is imported from its existing 9.0.2 registry package with
the published archive checksum verified (MIT OR Apache-2.0).
`chromiumoxide-import.json` and `swagger-import.json` record original hashes.

Both now depend on ZIP 9.0.5. Chromium's historical custom extractor copied
unconfined symlinks and Unix permission bits; it now delegates to the patched
ZIP extractor. Regression tests exercise ordinary browser files, path traversal,
escaping/existing symlinks, special permission bits and legitimate internal links.
The credential harness compiles the actual extractor source and runs these cases
in native CI. The fetcher's standalone default uses the same Tokio/Rustls mode
already explicitly selected by the application; production feature selection is
unchanged. Swagger's public integration stays on Utoipa 5.

These patches remove the old ZIP versions without importing a different browser
protocol client or changing the application's OpenAPI API. Retire each patch when
a pinned compatible upstream release supports the fixed ZIP version. Licences
retain their text; trailing blank lines are normalized.
