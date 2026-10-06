# AgntID Observatory

AgntID Observatory helps you understand an MCP server before an AI agent uses it. It reads the server’s advertised tools, schemas, instructions, prompts, and resource descriptions, then produces evidence, findings, and downloadable reports. It never invokes discovered tools.

Use it to review anonymous exposure, compare identities, inspect tool contracts, and track catalog changes. You can connect to a live Streamable HTTP endpoint or upload a saved JSON snapshot. No LLM or model API key is required for the deterministic analysis.

**Release status:** this checkout is under review for an initial open-source release. See the [release review](docs/RELEASE_REVIEW.md) for known security and correctness issues. A successful build does not establish that it is ready for public hosting.

Start with the [feature guide](docs/FEATURE_GUIDE.md) for workflows, examples, and interpretation. API endpoints and payloads are described in [OpenAPI](contracts/openapi.yaml); known contract discrepancies are recorded in the release review.

## Clone, build, and run with Docker Compose

Requirements: Git, Docker with Docker Compose v2, and an internet connection for the initial build. Make sure Docker is running and ports 3000 and 18080 are available.

Clone the source and build the application images locally:

```bash
git clone https://github.com/AGNTID-AI/observatory-mcp-scan.git
cd observatory-mcp-scan
docker compose up --build -d
docker compose ps
```

The first build downloads base images and dependencies and may take several minutes. Docker provides the Go, Node, and pnpm toolchains used by the build. Wait until `docker compose ps` shows both services as healthy, then open [http://localhost:3000](http://localhost:3000).

A realistic sample assessment is queued automatically on the first clean start. Data and generated reports are stored in the `observatory-data` volume.

The API is also available on `http://localhost:18080`; the web service forwards `/api/v1` to the API over the Compose network.

Check the API and inspect logs:

```bash
curl --fail http://localhost:18080/healthz
docker compose logs --tail=100
```

Stop the stack with `docker compose down`. Its named data volume is retained. Ports 3000 and 18080 must be free; see [troubleshooting](docs/FEATURE_GUIDE.md#troubleshooting) for changing the web port.

## Local development for contributors

Use this setup when developing the API or web application directly on your machine.

Requirements: Go 1.25+, Node 20+, and pnpm 8.10.5. The official MCP Go SDK v1.6.1 sets Go 1.25 as its module minimum.

```bash
cd apps/api
go run ./cmd/observatory
```

In a second terminal, from the repository root:

```bash
pnpm install
pnpm dev
```

The Next.js development server proxies `/api/v1` to `http://localhost:8080`.

## Assessment behavior

- Live assessments connect over Streamable HTTP, initialize an MCP session, and list tools, prompts, and resources using the official Go MCP SDK.
- OAuth-protected servers can be authorized through a browser flow using Dynamic Client Registration and PKCE S256. The resulting access token is encrypted, consumed by the queued assessment, and never returned to the browser application.
- A dedicated OAuth security-posture engine evaluates protected-resource and authorization-server metadata, registration support, PKCE advertisement, bearer-token transport methods, scopes, and challenge consistency without registering a client during posture-only scans.
- Live assessments always attempt anonymous access. Up to four supplied identity profiles are assessed in isolated sessions to compare catalog visibility without invoking tools.
- Portable deterministic intelligence classifies operation type, effects, sensitivity, blast radius, privilege, execution surface, schema quality, and annotation contradictions for every tool.
- Metadata content-integrity checks inspect server instructions, tools, schemas, prompts, and resource descriptions for explainable instruction-override, credential, egress, deception, and execution indicators.
- Per-tool contract readiness distinguishes observed declaration quality from runtime behavior that cannot be proven without invocation.
- Catalog fingerprints are compared with a recent completed or partial assessment for the same target, producing field-level drift and AgntID policy impact. The current baseline lookup has limitations described in the feature guide.
- Offline mode imports metadata-only JSON snapshots for CI or unreachable environments. Live-only evidence is unavailable; some stage labels currently show “completed” incorrectly (see the release review).
- Observatory highlights dangerous anonymous exposure and cross-tool risk chains, then previews read-only, read-write, and protected AgntID policy outcomes.
- Transport, authentication, authorization, protocol, tool classification, context, AI readiness, and bounded operational engines emit independent evidence.
- Findings come from YAML metadata and Rego policies in `rules/public`.
- Bearer tokens and permitted custom headers are encrypted in SQLite and deleted during normal terminal assessment cleanup. Error redaction and interrupted-job cleanup need strengthening before release (see the release review).
- Public and RFC1918 targets are permitted. Loopback, link-local, multicast, unspecified, cloud-metadata targets, cross-host redirects, and unsafe custom headers are blocked by default.
- HTML, Markdown, canonical JSON, and SARIF reports are generated from the same canonical model.

Catalog visibility is not treated as proof that a tool is executable. Authorization findings remain conservative unless differences are directly observed between supplied identities.

The implementation slices and portability boundaries are documented in [Tool Intelligence Implementation Plan](docs/TOOL_INTELLIGENCE_IMPLEMENTATION_PLAN.md).

## Offline and CI assessment

The UI accepts a JSON metadata snapshot. A reference input is available at [`fixtures/offline-snapshot.json`](fixtures/offline-snapshot.json). The same workflow can be queued through the API:

```bash
jq -n --slurpfile snapshot fixtures/offline-snapshot.json \
  '{mode:"offline",target:{protocol:"mcp",url:$snapshot[0].targetUrl},snapshot:$snapshot[0]}' \
  | curl --fail-with-body -H 'Content-Type: application/json' --data-binary @- http://localhost:18080/api/v1/assessments
```

The response contains `assessmentId`; the HTTP `Location` header gives the detail URL. Poll `/api/v1/assessments/<assessmentId>` until `status` is `completed`, `partial`, `failed`, or `canceled`. Download SARIF from `/api/v1/assessments/<assessmentId>/artifacts/assessment.sarif`. A full copy-and-paste example is in the [feature guide](docs/FEATURE_GUIDE.md#offline-assessment-through-the-api). Reuse `targetUrl` across pipeline runs to activate drift comparison. Snapshot mode makes no network request to the target and does not accept credentials.

## Important configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `OBSERVATORY_DATA_DIR` | `./data` | SQLite, encryption key, and artifacts |
| `OBSERVATORY_RULE_DIR` | `../../rules/public` | OPA rule bundle directory |
| `OBSERVATORY_WORKERS` | `2` | Concurrent assessment workers |
| `OBSERVATORY_ALLOW_LOOPBACK` | `false` | Explicitly enable loopback targets |
| `OBSERVATORY_CREDENTIAL_KEY` | generated locally | Optional external credential-encryption secret |
| `OBSERVATORY_OAUTH_CALLBACK_URL` | `http://localhost:3000/api/v1/oauth/callback` | Browser callback registered for local DCR authorization |
| `API_INTERNAL_URL` | `http://localhost:8080` | Server-side API proxy target for Next.js |

This first release is single-workspace and has no built-in login. The Compose ports bind to localhost; use an authenticated reverse proxy or VPN and restrict outbound access before exposing it externally. This does not provide isolation between users of the shared workspace.

OAuth sessions are intended to expire after ten minutes and be single-use. The release review records gaps in automatic expiry and concurrent consumption; do not rely on these guarantees until fixed. The access token is stored in the encrypted credential vault; normal consumption, cancellation, and terminal assessment cleanup remove the relevant envelope. Automatic expiry and interrupted cleanup require the fixes described in the release review. SDK-managed registration material is never persisted by Observatory. A remote authorization server may retain its dynamically registered client record according to that server's own lifecycle policy.

## Development and contributions

See [CONTRIBUTING.md](CONTRIBUTING.md) for the repository layout, checks, and how to propose changes. The [implementation plan](docs/TOOL_INTELLIGENCE_IMPLEMENTATION_PLAN.md) provides design context; it is not a test-completion record.

A license and a private vulnerability-reporting channel still need to be chosen before the open-source release. The source snapshot’s origin is recorded in [SOURCE_PROVENANCE.json](SOURCE_PROVENANCE.json); its hashes describe the original import, not subsequent edits.

## Deployment inside the parent AgntID repository

This source is vendored into `docker/services/free-mcp-report` and is wired into
the root and CD Compose stacks as `free-mcp-report-api` and
`free-mcp-report-web`. Traefik publishes the web service at
`https://free-mcp-report.<DOMAIN>` by default. Override the hostname with
`FREE_MCP_REPORT_HOST`.

These commands apply to the parent AgntID repository, which provides its own Makefile and Compose integration. They are not available in this standalone checkout:

From that parent repository root:

```bash
make free-mcp-report-build
make free-mcp-report-up
make free-mcp-report-health
make free-mcp-report-logs
```

Assessment data, generated reports, and the generated credential-encryption
key are stored in the `free-mcp-report-data` Docker volume. The integrated host
is intentionally public and uses Observatory's single shared workspace; do not
use it for private assessments unless appropriate access control and workspace isolation are added.
