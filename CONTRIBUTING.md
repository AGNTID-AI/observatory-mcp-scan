# Contributing to AgntID Observatory

This checkout is preparing for an initial open-source release. License terms and a private security-reporting channel must be established before inviting external contributions. See the [release review](docs/RELEASE_REVIEW.md) for current priorities. Do not put real credentials, private target metadata, or exploit details in public issues.

## Repository layout

- `apps/api`: Go HTTP API, assessment workers, SQLite storage, OAuth flow, scanners, and report generation.
- `apps/api/pkg`: reusable deterministic tool intelligence, content analysis, contract readiness, and catalog comparison.
- `apps/web`: Next.js dashboard and assessment/report interface.
- `rules/public`: YAML rule descriptions and Rego policies.
- `contracts/openapi.yaml`: API contract; known discrepancies are listed in the release review.
- `fixtures`: synthetic offline inputs.
- `docs`: user guidance, release review, and design context.

## Set up and check changes

Follow the [README](README.md) for tool versions and local or Docker setup. From the repository root:

```bash
pnpm install --frozen-lockfile
pnpm lint
pnpm type-check
pnpm build
```

From `apps/api`:

```bash
go test ./...
go test -race ./...
go vet ./...
```

The API’s SQLite driver uses CGO, so Go builds and race tests need an appropriate C toolchain. The Docker API build runs unit tests; the frontend build includes lint/type checks. Explicit checks remain useful when changing either package independently.

For dependency review, run `pnpm audit` and the official Go `govulncheck` tool with a compatible toolchain. Distinguish reachable vulnerabilities from dependency-only reports, and review fixes before updating the lockfile.

Use a clean, isolated data directory or Compose project when testing seed behavior. Use fixture credentials and controlled MCP endpoints for live/OAuth tests. Do not call a discovered tool to test authorization: metadata-only behavior is a product requirement.

## Propose a change

Explain the problem, the resulting behavior, and the checks you ran. Include a regression test for changes to credential handling, concurrency, persistence, protocol behavior, or report truthfulness. For UI changes, check keyboard use, narrow screens, loading states, and failure states.

Update the feature guide and API contract when behavior or payloads change. Rules should explain the evidence behind a finding and distinguish observed facts from inferred or simulated policy outcomes. Avoid implying that a advertised catalog proves tools can be executed or that a clean metadata scan establishes runtime safety.

Keep generated assessment data, keys, tokens, and local environment files out of commits. `SOURCE_PROVENANCE.json` records the original imported snapshot; do not silently regenerate it to conceal changes to that snapshot.
