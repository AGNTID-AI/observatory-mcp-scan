# Using AgntID Observatory

Observatory reads what an MCP server advertises and explains the risks and quality of those declarations. It does not execute tools, enforce policy on the target, or prove that a server behaves safely at runtime.

## Choose an assessment source

| Source | What you provide | What Observatory can establish |
| --- | --- | --- |
| Live | An HTTP or HTTPS MCP Streamable HTTP endpoint; optional credentials | Connection outcome, advertised metadata, anonymous visibility, and differences between supplied identities |
| Offline | A JSON snapshot of advertised metadata | Declaration quality, content warning patterns, policy previews, and catalog changes; no target requests |
| Sample | Automatically queued on the first clean start; also available through the API | An illustrative report for learning the interface; it is not a real target scan |

Stdio and legacy SSE-only servers are not supported as target transports. Live MCP sessions may use SSE responses as part of Streamable HTTP. Neither live nor offline assessments call `tools/call`, retrieve prompt bodies with `prompts/get`, or read resource contents with `resources/read`.

## Explore the application

1. Start the stack using the [README](../README.md). Open the dashboard to see the sample and recent assessments.
2. Choose **Assessments** to browse history or start an assessment. Open **Advanced options** when you need headers, a snapshot upload, or multiple identities.
3. Open an assessment for progress, connection status, evidence, findings, tool intelligence, identity comparisons, and report downloads. Running assessments can be canceled.
4. Open **Reports** for completed or partial reports. Reports can be printed and downloaded.
5. Use the assessment history comparison to review changes between runs of the same endpoint.
6. Use **MCP Directory** to browse eligible live assessments already in this workspace. It is not an external registry or an automatic discovery service. Directory filters cover category, authentication, risk, deployment, and recognized publisher hosts.
7. Use **Rules** to read the loaded checks and **Settings** to inspect the application’s advertised capabilities. Settings currently contains hard-coded limits; use deployment configuration as the source of truth until that issue is fixed.

All visitors share the same workspace. Assessments, reports, and supplied identity labels are not private to their creator. The directory’s public-facing wording does not create an access-control boundary.

## Assess a live server

Enter the full MCP endpoint, including its path (for example, `https://example.com/mcp`). A normal website URL may respond to HTTP probes but fail MCP initialization. HTTP support is useful for development; use HTTPS when supplying credentials.

An anonymous session is always attempted. Add up to four named identities when you want to compare visibility:

- **Bearer token:** paste a token issued for the target server.
- **Custom headers:** supply the target’s authentication or tenant headers. Host, Cookie, forwarding, proxy-authorization, and other unsafe headers are rejected. Use the bearer field for Authorization.
- **Browser OAuth:** name the identity and choose Connect. Observatory discovers metadata, dynamically registers a client when supported, and uses PKCE S256. Complete the browser flow before submitting the assessment. Servers without Dynamic Client Registration need a pre-issued token; the UI does not support arbitrary static OAuth client configuration.

Each identity gets its own MCP session. If Reader and Administrator advertise different tools, the report records that observed difference. Identical catalogs do not establish an authorization bypass: the server may enforce permissions only during execution, which Observatory does not test.

OAuth metadata inspection is separate from browser authorization. A posture-only assessment does not register a client or exchange tokens. Browser authorization does both, and the remote server may retain its registration record.

**Known release issues:** automatic token expiry, concurrent token consumption, and error redaction require fixes. See [RELEASE_REVIEW.md](RELEASE_REVIEW.md). The intended ten-minute, single-use OAuth behavior is not fully enforced yet.

## Understand the report

| Feature | What it tells you | Its limit |
| --- | --- | --- |
| Transport and authentication | Reachability, TLS-related observations, and anonymous initialization response | A successful HTTP response alone does not prove an MCP session or a correctly enforced security boundary |
| OAuth posture | Resource and authorization metadata, registration support, PKCE advertisement, bearer methods, scopes, and challenge consistency | Advertised support is not proof of runtime enforcement; failed probes must not be read as proof that OAuth is unnecessary |
| Protocol and catalog | Negotiated live protocol and advertised tools, prompts, resources, and instructions | Prompt/resource pagination is incomplete; catalog contents can be partial |
| Tool classification | Operation, effects, domain, sensitivity, blast radius, privilege, execution surface, and annotation contradictions | Deterministic inference with confidence and evidence; ambiguous capabilities can fall back to general/unknown categories |
| Schema and input/output boundaries | Missing descriptions, output schemas, constraints, sensitive fields, and execution-oriented inputs | Examines declarations, not actual argument validation or returned data |
| Content integrity | Warning patterns for instruction override, credential disclosure, execution, deception, and unintended data transfer | Inspects metadata text. No matched pattern does not prove absence of prompt injection |
| Contract readiness | Per-tool declaration quality, applicable checks, score, and coverage | Runtime behavior remains unverified |
| AI readiness and context | Description quality and estimated metadata token usage | Token counts are estimates, not measurements from a specific model tokenizer |
| Identity exposure | Which supplied identities can discover each tool and whether catalogs differ | Discoverability does not prove executability |
| Policy previews and risk chains | Illustrative read-only, read-write, and protected profile outcomes, plus risky capability combinations | Simulations; Observatory does not install or enforce policies on the target |
| Catalog drift | Added, removed, or changed declarations and their policy implications | Uses prior assessments of the same URL; current lookup only searches the latest 100 workspace assessments and can mix sources/identity coverage |
| Operational checks | Bounded live operational observations | Not a load test, uptime monitor, or performance benchmark |
| Findings and recommendations | YAML rule metadata plus Rego checks, severity, evidence, and suggested actions | A finding can describe a policy opportunity rather than a demonstrated exploit |

Read **coverage** alongside the overall score. A score of 100 with low coverage means the assessed evidence produced no score penalties; it does not certify the unassessed parts. Evidence distinguishes measured, imported, sample, inferred, and unavailable sources. Keep connection status separate from pipeline completion: a partial assessment can still generate a report after a connection failure.

Current offline stages sometimes display “completed” despite unavailable evidence. The Markdown report can also incorrectly describe an anonymous OAuth probe that never ran. Trust the source mode and underlying evidence, and consult the release review before publishing reports.

## Offline assessment through the API

Requirements: the Compose API running on port 18080, `curl`, and `jq`. Run these commands from the repository root:

```bash
assessment_id=$(
  jq -n --slurpfile snapshot fixtures/offline-snapshot.json \
    '{mode:"offline",target:{protocol:"mcp",url:$snapshot[0].targetUrl},snapshot:$snapshot[0]}' \
    | curl --fail-with-body -sS -H 'Content-Type: application/json' \
        --data-binary @- http://localhost:18080/api/v1/assessments \
    | jq -er '.assessmentId'
)

while true; do
  curl --fail-with-body -sS \
    "http://localhost:18080/api/v1/assessments/$assessment_id" \
    -o /tmp/observatory-assessment.json || break
  status=$(jq -r '.status' /tmp/observatory-assessment.json)
  case "$status" in
    completed|partial|failed|canceled) break ;;
  esac
  sleep 1
done

jq '{status, connectionStatus, scorecard, artifacts}' /tmp/observatory-assessment.json
curl --fail-with-body -sS \
  "http://localhost:18080/api/v1/assessments/$assessment_id/artifacts/assessment.sarif" \
  -o assessment.sarif
```

In a CI job, set a polling deadline and define your own failure threshold using findings and coverage. A completed job or a downloaded SARIF file is not by itself a pass/fail security decision. `partial`, `failed`, or `canceled` results require explicit handling; do not assume those states have a complete report set.

The reference snapshot includes two payment tools and one prompt. Use it as a shape example, not as a classifier acceptance benchmark: the current refund classification is generic. Keep `targetUrl` stable to compare repeated imports. Offline requests cannot contain credentials. The API limits snapshots to 1,000 tools and 1,000 combined prompt/resource entries.

Assessment event streams are available at `/api/v1/assessments/<id>/events`. Supply `after` or `Last-Event-ID` to resume. Large terminal-event backlogs currently have a replay limitation described in the release review.

## Export formats

Every normally completed assessment generates:

| File | Intended use |
| --- | --- |
| `executive-summary.html` and `executive-summary.md` | A short explanation for decision makers |
| `technical-report.html` and `technical-report.md` | Findings, evidence, tool details, and recommendations |
| `assessment.json` | Machine-readable assessment data |
| `assessment.sarif` | SARIF 2.1.0 findings for compatible analysis tooling |

The JSON export currently snapshots the pipeline before its final status is saved, so it can contain `running` and 95% progress for a completed assessment. Use the detail endpoint for terminal status until fixed. Hashes and sizes accompany the artifact list; verify them when transporting reports.

## Configuration and data

The [README configuration table](../README.md#important-configuration) lists the main variables. `OBSERVATORY_LISTEN` also controls the API bind address (default `:8080`). The standalone API defaults to a local data directory and expects rules relative to `apps/api`; Docker sets both paths explicitly.

SQLite stores assessment data, events, and encrypted credential envelopes. The generated encryption key and exported reports share the data directory. Normal completion deletes scan credential envelopes. Interrupted running jobs currently lack startup recovery, and OAuth expiry cleanup is incomplete. Metadata supplied by a target can itself contain sensitive text; encryption of submitted credentials does not encrypt reports or all assessment data.

The network policy permits public and private-network targets, pins resolved addresses for single-host requests, and blocks loopback by default, link-local, multicast, unspecified addresses, known metadata targets, and cross-host target redirects. OAuth discovery can cross hosts and revalidates destinations. Credentials over HTTP and same-host HTTPS-to-HTTP redirects need tighter handling before release. Protect outbound access as well as inbound access when deploying in a network with private services.

`API_INTERNAL_URL` is used when Next.js builds its proxy rewrites. Changing it only in a prebuilt runtime container is not a reliable way to retarget the proxy; rebuild for the desired API destination. The browser OAuth callback URL must match the actual browser origin.

## Troubleshooting

- **Port already allocated:** stop your own conflicting service or use a Compose override. Do not stop unrelated services. With Compose supporting `!override`, create `compose.local.yaml`:

  ```yaml
  services:
    free-mcp-report-web:
      ports: !override
        - "127.0.0.1:13000:3000"
    free-mcp-report-api:
      environment:
        OBSERVATORY_OAUTH_CALLBACK_URL: "http://localhost:13000/api/v1/oauth/callback"
  ```

  Run `docker compose -f docker-compose.yml -f compose.local.yaml up --build -d` and open `http://localhost:13000`.
- **401/403 or authentication-required:** connect OAuth if DCR is supported, or supply a token issued for that endpoint.
- **HTTP works but MCP fails:** verify the endpoint path and Streamable HTTP support.
- **Loopback blocked:** this is the default target policy. Enable `OBSERVATORY_ALLOW_LOOPBACK` only for your controlled development environment. Inside Docker, localhost is the container itself.
- **No drift comparison:** use the exact same target URL and a previous completed/partial assessment with tools. The current lookup is bounded to 100 recent workspace entries.
- **Rules fail to load locally:** start the API from `apps/api`, or set `OBSERVATORY_RULE_DIR` to the actual rule directory.
- **Local setup fails:** install a supported Go and Node version plus pnpm 8.10.5. See the README requirements; the host tools may differ from Docker’s tools.
