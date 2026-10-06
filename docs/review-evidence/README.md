# Review evidence

Captured on 2026-10-06 for the imported source before application fixes.

- `frontend-audit.json`: summarized `pnpm audit --json` output, including advisory URLs and version ranges. The registry summary reports 53 vulnerability occurrences; the advisory map contains 52 records. Neither count is a count of proven exploits in this application.
- `govulncheck.txt`: official Go source scan output. The checker downloaded Go 1.26.8; it did not scan the shipped Go 1.25.5 binary/standard library.
- `oauth_review_test.go`: fixture probes for atomic one-time consumption and cleanup without polling.
- `network_review_test.go`: controlled concurrent HTTP dialing probe for the race detector.
- `regression-probes.txt`: captured failure/race output. Original probes were mounted from temporary files; the copies here were subsequently formatted with gofmt, so diagnostic line numbers can differ.

The probes intentionally fail on current code. See the [release review](../RELEASE_REVIEW.md) for reproduction commands and fixes. They use synthetic tokens and controlled local servers. Keep the regression scenarios when implementing fixes, and move appropriate assertions into the normal test packages.

Advisory ranges change over time. Rerun the scans after upgrades and before tagging a release. Primary advisory links support the dependency findings; actual exposure still depends on configuration and reachable behavior.
