# Vector enrichment compatibility source

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
