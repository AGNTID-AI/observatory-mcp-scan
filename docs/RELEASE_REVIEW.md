# Open-source release review

Review date: 2026-10-06. Scope: the standalone imported checkout, its Go API and intelligence packages, Next.js application, rules, Docker setup, API contract, and documentation.

**Recommendation: hold the public release until the release gates below are met.** The application builds and its main sample/offline workflows work, but known vulnerable dependencies and confirmed credential/concurrency bugs remain. Source publication readiness and readiness to host an unauthenticated public service are separate decisions; publishing the source does not make the deployment safe.

No application-code fixes were made during this review. README and supporting documentation were improved to describe current behavior and limitations. This review is a prioritized assessment, not a guarantee that every vulnerability has been found.

## Verification and evidence

| Check | Result |
| --- | --- |
| Docker API and frontend builds | Passed; frontend lint and type validation passed |
| Existing Go unit suite | 41 tests passed |
| Existing Go suite with `-race -cover` | Passed; important integration paths are absent from the tests |
| `go vet ./...` | Passed |
| Sample assessment on clean Compose volume | Automatically queued and completed |
| README offline API workflow | Completed, two tools imported, six reports produced |
| Artifact downloads and SHA-256 | All six downloads matched advertised hashes; SARIF parsed as 2.1.0 |
| Web routes and API proxy | HTTP smoke checks passed; both containers healthy |
| Unchanged and modified snapshots | Stable baseline and one modified tool correctly detected |
| Invalid offline credential requests | Rejected with HTTP 400 |
| API/schema and canonical-report probes | Confirmed discrepancies described below |
| Temporary OAuth/concurrency probes | Confirmed duplicate consumption, lazy expiry, and network data race |
| Frontend lockfile audit | 53 vulnerability occurrences across 52 advisory records: 3 critical, 30 high, 18 moderate, 2 low |
| Official Go vulnerability scan | 3 symbol-level findings from 2 modules; additional import/module-only findings |
| Targeted secret-pattern scan | No obvious real secret matched; fixture tokens were present |

Frontend audit counts are registry-reported vulnerability occurrences, not distinct proven exploits. The JSON summary reports 53 occurrences and contains 52 advisory records. Some require configurations absent from this checkout. The React Flight RCE advisory applies to the Next.js App Router version in use, so it is a release blocker without relying on the aggregate count. No exploit payload was sent.

The Go scan required automatic download of Go 1.26.8 because current `govulncheck` requires Go 1.26. Its module findings are useful, but this source scan does not constitute a vulnerability assessment of the Docker binary’s older Go 1.25.5 standard library. Perform a separate binary/toolchain scan after upgrades.

Reproducible fixture probes and advisory summaries are in [review-evidence](review-evidence/). The probes assert the desired behavior and intentionally fail on the current implementation. They are stored outside the normal test packages to avoid presenting review probes as production tests. To reproduce with Docker:

```bash
docker build --target build -t observatory-review-api -f apps/api/Dockerfile .
docker run --rm \
  -v "$PWD/docs/review-evidence/oauth_review_test.go:/src/internal/oauthflow/review_test.go:ro" \
  -v "$PWD/docs/review-evidence/network_review_test.go:/src/internal/scanner/review_test.go:ro" \
  observatory-review-api go test -race -run TestReview -v ./internal/oauthflow ./internal/scanner
```

## Release gates

1. Upgrade vulnerable production dependencies and toolchains, refresh the lockfile, rerun builds and both vulnerability scans, and triage any remaining advisory with its actual applicability.
2. Fix credential lifecycle, single-use OAuth consumption, secret redaction, network concurrency, and interrupted-job recovery. Add meaningful regression tests in the normal packages.
3. Correct reports, offline status labels, discovery limits/pagination, and the API contract so users can trust exported evidence.
4. Define supported deployment boundaries. Do not present the current public, shared workspace as suitable for confidential scans. If public hosting is a release goal, add access control, outbound restrictions, abuse limits, and retention controls before launching it.
5. Choose and add the source license, confirm the imported source and brand assets are approved for distribution, establish a private security-reporting channel and support policy, and add CI/release checks.

## Findings

### R01 — Blocker: vulnerable frontend and Go dependencies

[apps/web/package.json](../apps/web/package.json) pins Next.js 15.5.2 and React/React DOM 19.1.0. The App Router stack falls within the published React Flight unauthenticated RCE advisory range. The lockfile audit also reports other Next.js, sharp, PostCSS, and tooling advisories. Upgrade the framework and compatible React packages together and update `eslint-config-next`; choosing only the original December patch is insufficient for the current advisory set.

Primary references: [React RSC advisory](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components), [Next.js follow-up security update](https://nextjs.org/blog/security-update-2025-12-11). The captured registry audit includes later advisories and their reported patched ranges; verify the release line again when applying fixes.

`govulncheck` reports symbol-level findings in `golang.org/x/text` v0.31.0 and `go.opentelemetry.io/otel/sdk` v1.38.0: [GO-2026-5970](https://pkg.go.dev/vuln/GO-2026-5970), [GO-2026-6505](https://pkg.go.dev/vuln/GO-2026-6505), and [GO-2026-4394](https://pkg.go.dev/vuln/GO-2026-4394). Traces include initialization through GORM/OPA; this is static reachability, not a demonstrated remote exploit of the Observatory API. Upgrade or document prerequisites for each residual finding. Also scan the final container OS packages and the compiled Go standard library.

### R02 — Release prerequisite: licensing, contribution, and security policy missing

The imported checkout had no LICENSE, SECURITY.md, CONTRIBUTING.md, CI workflow, release procedure, or third-party notice inventory. The provenance file names the parent private source snapshot; it does not establish license terms or rights for logos. There are no Git commits in this standalone checkout, and all imported files were untracked at review time, so history scanning cannot be completed here.

CONTRIBUTING.md was added as preparation, with unresolved license/reporting decisions stated explicitly. Before release, the maintainer must choose the license, approve distribution of imported source/assets, provide a private vulnerability channel, define supported versions, and add the relevant policy files. Avoid publishing placeholders that promise a nonexistent support process.

### R03 — High for public hosting: unauthenticated shared workspace can access private targets

[HTTP routes](../apps/api/internal/httpapi/server.go) have no authentication or ownership checks. Any reachable visitor can list assessments, download reports, cancel jobs, and submit scans. [Network policy](../apps/api/internal/scanner/network.go) deliberately permits private addresses. An unauthenticated public instance therefore lets visitors cause metadata/probe requests to internal services and browse other visitors’ metadata. UUIDs do not provide isolation because assessments are enumerable.

This is an intentional documented deployment model, rather than an undisclosed login feature. It still needs a clear release decision. Keep standalone bindings on localhost; for shared hosting, require authenticated access, authorization per workspace/job, restricted outbound destinations, and request/job limits. An authenticated proxy alone does not isolate multiple users inside the shared workspace.

### R04 — High, confirmed: OAuth token expiry relies on polling; sessions accumulate

In [oauthflow/service.go](../apps/api/internal/oauthflow/service.go), successful authorization ends `run`; expiration/deletion then happens only in `Get`. Closing the browser or abandoning the form can leave an encrypted authorized token after ten minutes until a later read or process restart. The `sessions` map is never pruned. The fixture expiry probe confirmed a token remains without polling.

Add expiry cleanup independent of requests, prune terminal sessions, remove state mappings, and coordinate expiry/cancel with token exchange so late writes cannot restore a canceled token. Check token expiry as well as session expiry. Verify cleanup with an injected clock rather than long sleeps.

### R05 — High, confirmed: OAuth consumption is not atomic

`Consume` reads authorized status, fetches the token, deletes it, and changes status in separate operations. Two callers can both pass the checks and read the same token before deletion. A synchronized fixture vault made both concurrent callers return the token, contradicting the documented single-use guarantee.

Reserve/transition the session under a lock or use an atomic consume operation, and handle rollback/errors intentionally. Validate the entire assessment request before consuming any OAuth sessions: current profile-by-profile consumption can consume earlier tokens before a later invalid profile or failed enqueue is discovered.

### R06 — High: submitted credentials can leak through target-controlled errors

[scanner/engines.go](../apps/api/internal/scanner/engines.go) `redactError` only truncates text. Raw `runErr.Error()` is saved in stage messages, discovery facts, and events by [service/manager.go](../apps/api/internal/service/manager.go). A target that echoes an Authorization value or custom-header secret in its error can cause that value to enter unencrypted assessment data and reports. OAuth regex redaction only covers a small set of named token patterns.

This finding follows the concrete error propagation path; no real credential was used to exploit it. Remove known submitted secret values at every persistence/logging/output boundary, provide a safe diagnostic model, and test fixture secrets echoed by a controlled target. Clarify that metadata itself can contain secrets and is stored in plaintext.

### R07 — High: credentials can be sent over plaintext or downgraded redirects

The policy accepts HTTP targets. Redirect validation compares hostname, not full origin or scheme, so the same hostname can redirect HTTPS to HTTP or another port. The custom-header wrapper reapplies supplied headers on outgoing requests, and standard Authorization handling does not create an HTTPS-only guarantee.

Require HTTPS for credentialed live/OAuth requests outside explicitly controlled development, reject credentialed downgrade redirects, and define whether a same-host port change is permitted. Add controlled redirect tests. Hostname pinning and blocked cross-host redirects are useful protections but do not address this path.

### R08 — High, confirmed: outbound dial counter has a data race

`NetworkPolicy.Client` closes over `idx`, reads it at `network.go:83`, and increments it without synchronization. `http.Transport` can dial concurrently. The 30-request fixture probe triggered the Go race detector at that code.

Use an atomic counter, a lock, or deterministic address selection. Extend network tests to concurrent dialing and redirects; the existing race suite passed because it did not exercise this path. `MultiHostClient` also creates a new transport per request without explicit idle-connection lifecycle handling; review resource reuse/cleanup under load.

### R09 — High: jobs become claimable before credentials are ready; running jobs lack recovery

`Manager.Create` inserts a queued assessment before saving requested profiles and writing its credential envelope. The periodic worker can claim it between those operations and scan with missing credentials; its terminal save can race the creator’s queued save. A vault failure leaves an already queued job despite the API returning an error.

Publish a job as queued only after all required state is durable, preferably within a transaction or an explicit preparation state. On startup, reconcile interrupted `running` rows: `ClaimNext` only selects queued jobs, and startup only removes `oauth-` credentials. Abrupt termination can strand running assessments and their scan credentials. Test enqueue timing, crash recovery, and persistence failures. SQLite’s `FOR UPDATE` abstraction is not a substitute for a tested claim strategy across processes.

### R10 — High for public hosting: advertised response and item bounds are not enforced end to end

Settings advertises a 5 MiB response bound and 1,000 items. The shared outbound transport does not implement a general body bound; SDK response limits were not established by this review. `ListTools` checks count only before requesting a page and appends the entire page. Prompts/resources have no count cap in live discovery. Empty repeated cursors are not detected. Jobs, OAuth sessions, events, and stored reports have no retention/quota controls. API request decoding limits reads but does not reliably reject trailing bytes or classify oversized input as 413; the server only sets a header-read timeout.

Enforce byte/item/page/depth limits at actual consumption boundaries, detect cursor loops, reject trailing JSON and oversize bodies, bound request bodies/time without breaking SSE, and add queue/rate/storage limits for public deployments. Use hostile-but-bounded fixtures, not internet stress tests.

### R11 — Medium, confirmed: exported canonical JSON records an unfinished job

Report generation marshals the assessment while `status` is `running`, `progress` is 95, and the report stage is running. Terminal status is saved afterward. A real completed offline assessment had API status `completed` but downloaded JSON status `running`, progress 95, and no `completedAt`. Exported artifact metadata is also generated before the final artifact set is attached.

Define a final canonical report snapshot and finalize state consistently with generation outcomes. Add a test comparing semantically relevant API fields and exported JSON; checking that both parse is insufficient.

### R12 — Medium, confirmed: offline and failed probes are described as successful observations

Only authorization has a special `not-assessed` stage override. Offline transport, authentication, OAuth, and operational engines return unavailable evidence yet get “completed” status. The offline technical Markdown report says “OAuth protection was not required by the anonymous initialization probe,” although offline mode makes no probe. `InspectOAuth` also treats any response other than 401/403 as unprotected, including errors such as 500.

Operational probing also treats three failed HEAD requests as a consistent latency sample rather than failed availability; record success/error status for each probe.

Use explicit assessed/unavailable/error outcomes consistently in stage status, OAuth posture, scorecards, and each report format. Do not conflate absent protection with failed or missing evidence. Add offline, HTTP error, and failed-initialization report tests.

### R13 — Medium, confirmed: API contract and runtime validation disagree

`Assessment` extends `AssessmentSummary`, requiring top-level `overallScore` and `coverage`, but detail responses place them under `scorecard`. The API accepts `snapshot: {}` even though OpenAPI requires snapshot name/tools, and accepts a non-MCP target protocol while silently recording MCP. The runtime enforces 1,000 combined prompt/resource entries while OpenAPI declares independent 1,000-entry arrays. Documented label length is not validated. Error responses and snapshot-only target fallback are incompletely modeled.

Model summary and detail separately, validate protocol/name/labels/body shape, specify mutually exclusive modes/credentials, and contract-test real responses against OpenAPI. `/settings` contains hard-coded workers/loopback/limits and can contradict deployment variables; return effective settings rather than constants.

### R14 — Medium: live catalog completeness and baseline selection can mislead

Tools paginate, but prompt/resource lists read only their first page and silently ignore list failures. Drift baseline selection searches only the latest 100 assessments globally, accepts partial results, skips empty catalogs, and does not isolate source mode or comparable identity coverage. A target with older history can appear to have no baseline; different identity sets can produce apparent drift that is access variation.

Paginate all supported catalogs, expose list truncation/failure, query a baseline by target with source/identity comparability, and record the comparison scope. Handle an intentionally empty catalog as valid evidence. The UI history/directory also fetches only 100 assessments and lacks full pagination.

### R15 — Medium: key loading and artifact size handling can silently lose data

`loadKey` replaces an existing unreadable or incorrectly sized key instead of failing closed. Corrupt/misconfigured key state can therefore make prior envelopes undecryptable. Use exclusive/atomic initial key creation, reject invalid existing keys, and document backup/key rotation behavior. An external credential key is hashed directly; require high-entropy input rather than implying any memorable password is adequate.

`FileArtifacts.Put` silently stops at 25 MiB with `LimitReader`, then publishes a hash of the truncated file as if generation succeeded. Detect overflow, return an explicit error, and remove incomplete temporary files. Add corruption and large-report regression tests.

### R16 — Medium: terminal SSE replay can drop a large event backlog

`ListAfter` limits batches to 250 events. `streamEvents` sends one batch and returns immediately if the assessment is terminal, so a reconnect to a completed assessment can miss later events. Drain all remaining batches before closing; validate assessment existence before returning an SSE response, and test reconnection with more than 250 events.

### R17 — Medium: integration verification and release automation are missing

Coverage showed HTTP API and manager at 0%; scanner 22.9% and storage 21.3%. Intelligence packages had stronger coverage (about 81–91%). Passing unit tests do not establish live discovery, worker recovery, report consistency, or UI behavior. There are no browser tests or CI workflows. Dense one-line UI functions hinder review and future maintenance.

Add CI for locked install, formatting/lint/types/build, Go unit/race/vet, contract validation, dependency checks, and isolated Compose smoke tests. Add controlled live MCP tests proving no tools are invoked, paginated discovery, OAuth error/expiry/consumption tests, and persistence-failure tests. Run keyboard/accessibility/responsive browser checks. Establish dependency update cadence, an SBOM/notice process, image scanning, and release tags/changelog. Consider a formatter for the dense frontend code after correctness fixes. Expand ignore rules for `.env.*`, credential keys, custom data directories, and local Compose overrides; the current `.dockerignore` does not exclude environment files from build contexts. Verify the actual release archive and image contents, not just Git status.

## Documentation coverage and changes

The original README listed most engines but gave little help choosing a workflow or interpreting results. It also led with parent-repository commands unavailable here, implied a returned assessment URL in JSON, and overstated cleanup/status guarantees.

The README now starts with the standalone use case and setup, links the feature guide and review, clarifies polling and parent integration, and acknowledges known implementation gaps. [FEATURE_GUIDE.md](FEATURE_GUIDE.md) covers live/offline/sample modes, browser OAuth versus posture scans, tokens/headers, identity comparisons, all analysis families, policy simulations, findings/evidence/coverage, drift, history, directory, reports, API events, configuration, data handling, CI usage, and troubleshooting.

CONTRIBUTING.md describes the package layout and checks. Licensing and security contacts remain explicit maintainer decisions. The design plan’s aspirational verification list is distinguished from work actually tested.

## Strengths to preserve

The metadata-only boundary is clear and supported by list-based discovery. Deterministic intelligence packages have useful tests and per-dimension confidence. Credentials use AES-GCM with assessment IDs as associated data; normal terminal cleanup deletes envelopes. Single-host resolution is pinned to checked addresses, and common metadata/link-local/loopback targets are blocked. Report HTML uses Go’s escaping templates, and downloadable HTML has a restrictive CSP. Compose exposes services on localhost, uses non-root runtime users, and sets no-new-privileges. Rule metadata and Rego keep findings explainable.

## Limits of this review

HTTP smoke checks do not verify browser hydration, keyboard accessibility, or responsive layouts. No external live MCP server or real OAuth provider was used. Fixture OAuth tests exercise the SDK flow; the additional probes isolate confirmed lifecycle/concurrency defects. Full source-history secrets scanning, container OS/binary vulnerability scanning, transitive license inventory, hostile input fuzzing, restart-failure injection, and external penetration testing remain outstanding. No source or deployment was published, and no real credentials were used in the review probes.
