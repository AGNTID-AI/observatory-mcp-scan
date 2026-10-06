# AgntID Observatory Tool Intelligence Implementation Plan

## Outcome

Turn the Observatory from a metadata scanner into an identity-aware preview of
AgntID intelligence and policy outcomes, without invoking MCP tools.

The experience must answer four questions:

1. What can this MCP server advertise?
2. What does AgntID infer about every tool and schema?
3. Which identities can discover each capability?
4. What would AgntID protection profiles and policies change?

## Safety and truthfulness boundary

- Only `initialize`, list operations, OAuth metadata, and safe transport probes run.
- Every credential profile uses an isolated MCP session and HTTP client.
- Credentials remain in the encrypted, short-lived vault and are deleted at terminal completion.
- `discoverable` never means `executable`.
- Tool behavior and policy impact are labelled as inferred or simulated.
- No invalid-argument invocation is used as an authorization probe.

## Delivery slices

### 1. Portable tool intelligence

- Add an AgntID-aligned taxonomy for operation, domain, blast radius,
  sensitivity, criticality, privilege, execution surface, and effects.
- Record per-dimension confidence and evidence.
- Preserve declared MCP annotations and detect contradictions with inference.
- Add a discovery-safe JSON Schema analyzer.
- Generate stable catalog and tool fingerprints.

### 2. Identity exposure map

- Accept Anonymous plus multiple named bearer/custom-header profiles.
- Run isolated discovery for each profile.
- Produce tool-by-identity visibility, catalog fingerprints, and differences.
- Report catalog-equivalent identities as `isolation not observed`, not as an
  authorization bypass.

### 3. Policy preview

- Simulate AgntID Read Only, Read Write, and Protected/All profiles.
- Explain why each tool is visible, hidden, or requires approval.
- Detect dangerous capability combinations such as private-data access plus
  untrusted/open-world input plus external communication.

### 4. Product surfaces

- Extend API/domain contracts and reports.
- Add Identity & Policy and expanded Tool Intelligence views.
- Add rule-backed findings for destructive anonymous exposure, missing catalog
  separation, annotation conflicts, loose schemas, and risky capability chains.
- Keep conversion language focused on continuous enforcement, scoped
  credentials, approval, and auditability available in AgntID.

## Verification

- Unit tests for taxonomy, schema, policy, fingerprint, and identity comparison.
- API tests for multiple credential profiles and secret redaction.
- Production frontend/backend builds.
- Docker Compose health and sample-assessment smoke test.
- Browser QA of desktop and responsive assessment views.
