"use client";

import { useEffect, useMemo, useState } from "react";
import type { LucideIcon } from "lucide-react";
import {
  Activity,
  BadgeCheck,
  BookOpenCheck,
  Boxes,
  Braces,
  ChevronDown,
  CircleGauge,
  Fingerprint,
  KeyRound,
  Scale,
  Search,
  ShieldCheck,
} from "lucide-react";
import { api } from "@/lib/api";
import type { Rule } from "@/lib/types";
import { PageHeading, StatusBadge } from "@/components/page";

type CapabilityId = "authentication" | "identity" | "authorization" | "catalog" | "schemas" | "operational" | "governance";
type RuntimeLevel = "Supported" | "Partial" | "Not primary";

type Capability = {
  id: CapabilityId;
  title: string;
  description: string;
  protection: string;
  icon: LucideIcon;
};

const capabilities: Capability[] = [
  { id: "authentication", title: "Authentication", description: "Session access, OAuth discovery, token transport, and secure client registration.", protection: "Protects how clients prove identity before accessing an MCP endpoint.", icon: KeyRound },
  { id: "identity", title: "Identity", description: "Credential boundaries and separation of model context from secret material.", protection: "Protects human, workload, and agent credentials from entering model-visible inputs.", icon: Fingerprint },
  { id: "authorization", title: "Authorization", description: "Capability exposure, identity-aware access, approvals, and multi-tool risk chains.", protection: "Protects which identities can discover or use high-impact capabilities.", icon: ShieldCheck },
  { id: "catalog", title: "Catalog", description: "Tool declarations, descriptions, metadata integrity, and context efficiency.", protection: "Protects the accuracy and trustworthiness of the catalog an agent reasons over.", icon: Boxes },
  { id: "schemas", title: "Schemas", description: "Input constraints, output contracts, and tool contract readiness.", protection: "Protects the boundaries of values entering and leaving MCP tools.", icon: Braces },
  { id: "operational", title: "Operational", description: "Connectivity, transport security, initialization, and metadata latency.", protection: "Protects reliable and secure operation of the MCP endpoint.", icon: Activity },
  { id: "governance", title: "Governance", description: "Catalog drift, fingerprints, and review of changed capabilities.", protection: "Protects approved capability baselines from silent or unreviewed change.", icon: Scale },
];

export default function RuleExplorer() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [capability, setCapability] = useState<"all" | CapabilityId>("all");
  const [severity, setSeverity] = useState("all");
  const [support, setSupport] = useState("all");

  useEffect(() => {
    api.rules().then(response => setRules(response.items)).finally(() => setLoading(false));
  }, []);

  const filtered = useMemo(() => rules.filter(rule => {
    const ruleCapability = capabilityForRule(rule).id;
    const runtime = runtimeSupport(rule).level;
    const text = `${rule.id} ${rule.title} ${rule.description} ${rule.whyItMatters} ${rule.category}`.toLowerCase();
    return (capability === "all" || ruleCapability === capability) &&
      (severity === "all" || rule.severity === severity) &&
      (support === "all" || runtime === support) &&
      text.includes(query.toLowerCase());
  }), [rules, query, capability, severity, support]);

  const grouped = capabilities.map(item => ({ capability: item, rules: filtered.filter(rule => capabilityForRule(rule).id === item.id) })).filter(group => group.rules.length > 0);

  return <div className="capability-rule-explorer">
    <PageHeading
      eyebrow="Policy intelligence"
      title="Rule Explorer"
      description="Understand the protection intent behind every MCP readiness rule."
      actions={<span className="badge completed"><ShieldCheck size={12}/>{rules.filter(rule => rule.enabled).length} active rules</span>}
    />

    <section className="rule-explorer-intro">
      <div><span><BookOpenCheck size={18}/></span><div><strong>Rules organized by what they protect</strong><p>Start with a capability, then expand a rule for its reasoning, example, and remediation context.</p></div></div>
      <p>Rules assess declared metadata and observable posture. They do not execute MCP tools or test authorization enforcement.</p>
    </section>

    <section className="rule-capability-index" aria-label="Rule capabilities">
      <button className={capability === "all" ? "active" : ""} onClick={() => setCapability("all")}><span><CircleGauge size={17}/></span><div><strong>All capabilities</strong><small>{rules.length} rules</small></div></button>
      {capabilities.map(item => {
        const Icon = item.icon;
        const count = rules.filter(rule => capabilityForRule(rule).id === item.id).length;
        return <button key={item.id} className={capability === item.id ? "active" : ""} onClick={() => setCapability(item.id)}><span><Icon size={17}/></span><div><strong>{item.title}</strong><small>{count} {count === 1 ? "rule" : "rules"}</small></div></button>;
      })}
    </section>

    <section className="card rule-explorer-controls" aria-label="Rule filters">
      <div className="rule-explorer-search"><Search size={15}/><input className="input" placeholder="Search by protection, issue, or rule ID…" value={query} onChange={event => setQuery(event.target.value)}/></div>
      <label><span>Severity</span><select className="select" value={severity} onChange={event => setSeverity(event.target.value)}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Informational</option></select></label>
      <label><span>AgentID Runtime</span><select className="select" value={support} onChange={event => setSupport(event.target.value)}><option value="all">All support levels</option><option>Supported</option><option>Partial</option><option>Not primary</option></select></label>
    </section>

    <div className="rule-results-summary"><strong>{filtered.length} rules</strong><span>across {grouped.length} {grouped.length === 1 ? "capability" : "capabilities"}</span></div>

    {loading ? <div className="card rule-explorer-empty" role="status" aria-live="polite" aria-busy="true">Loading rule protections…</div> : grouped.length === 0 ? <div className="card rule-explorer-empty"><BookOpenCheck size={25}/><strong>No rules match these filters.</strong><button className="button" onClick={() => { setQuery(""); setCapability("all"); setSeverity("all"); setSupport("all"); }}>Clear filters</button></div> : <div className="capability-rule-groups">{grouped.map(group => <CapabilityGroup key={group.capability.id} capability={group.capability} rules={group.rules}/>)}</div>}
  </div>;
}

function CapabilityGroup({ capability, rules }: { capability: Capability; rules: Rule[] }) {
  const Icon = capability.icon;
  return <section className="card capability-rule-group" aria-labelledby={`${capability.id}-rules-title`}>
    <header className="capability-group-header"><span><Icon size={18}/></span><div><div className="section-label">Protection capability</div><h2 id={`${capability.id}-rules-title`}>{capability.title}</h2><p>{capability.description}</p></div><small>{rules.length} {rules.length === 1 ? "rule" : "rules"}</small></header>
    <div className="capability-protection-statement"><ShieldCheck size={14}/><span>{capability.protection}</span></div>
    <div className="capability-rule-list">{rules.map((rule, index) => <CapabilityRule key={rule.id} rule={rule} index={index + 1}/>)}</div>
  </section>;
}

function CapabilityRule({ rule, index }: { rule: Rule; index: number }) {
  const runtime = runtimeSupport(rule);
  return <details className="capability-rule-item">
    <summary>
      <span className="capability-rule-number">{String(index).padStart(2, "0")}</span>
      <div><h3>{rule.title}</h3><p>{rule.description}</p></div>
      <div className="capability-rule-badges"><StatusBadge value={rule.severity}/><span className={`runtime-support-badge ${runtimeClass(runtime.level)}`}><BadgeCheck size={10}/>{runtime.level}</span></div>
      <ChevronDown size={15}/>
    </summary>
    <div className="capability-rule-detail">
      <div className="rule-explanation-grid">
        <article><span>Description</span><p>{rule.description}</p></article>
        <article><span>Reasoning</span><p>{rule.whyItMatters}</p></article>
        <article className="rule-example"><span>Example</span><RuleExample rule={rule}/></article>
      </div>
      <div className="rule-runtime-support">
        <span><BadgeCheck size={16}/></span>
        <div><div><strong>AgentID Runtime support</strong><span className={`runtime-support-badge ${runtimeClass(runtime.level)}`}>{runtime.level}</span></div><p>{runtime.detail}</p></div>
      </div>
      <div className="rule-recommended-response"><strong>Recommended response</strong><p>{rule.recommendation}</p></div>
      <details className="rule-technical-detail"><summary>Technical rule details <ChevronDown size={13}/></summary><dl><div><dt>Rule ID</dt><dd>{rule.id}</dd></div><div><dt>Source category</dt><dd>{rule.category}</dd></div><div><dt>Classification</dt><dd>{humanize(rule.classification || "posture")}</dd></div><div><dt>Dimension</dt><dd>{humanize(rule.dimension)}</dd></div></dl>{rule.rego && <details className="rego-disclosure"><summary>View Rego source</summary><pre>{rule.rego}</pre></details>}</details>
    </div>
  </details>;
}

function RuleExample({ rule }: { rule: Rule }) {
  if (rule.replay) return <div className="rule-example-sequence"><p><strong>Scenario:</strong> {rule.replay.trigger}</p><p><strong>Without explicit policy:</strong> {rule.replay.unprotectedPath}</p><p><strong>Protected outcome:</strong> {rule.replay.protectedOutcome}</p></div>;
  return <p>{exampleForRule(rule)}</p>;
}

function capabilityForRule(rule: Rule): Capability {
  const category = rule.category.toLowerCase();
  if (category === "credential boundary") return capabilityById("identity");
  if (category.includes("oauth") || category === "authentication") return capabilityById("authentication");
  if (["authorization exposure", "capability exposure", "capability chain", "policy opportunity"].includes(category)) return capabilityById("authorization");
  if (["schema safety", "tool contract readiness", "input boundary", "output trust boundary"].includes(category)) return capabilityById("schemas");
  if (["catalog governance"].includes(category)) return capabilityById("governance");
  if (["operational", "transport"].includes(category)) return capabilityById("operational");
  return capabilityById("catalog");
}

function capabilityById(id: CapabilityId) { return capabilities.find(capability => capability.id === id)!; }

function runtimeSupport(rule: Rule): { level: RuntimeLevel; detail: string } {
  const classification = rule.classification || "posture";
  if (["capability-chain", "policy-opportunity", "credential-boundary", "exposure"].includes(classification)) return { level: "Supported", detail: "Runtime can apply identity-aware allow, deny, approval, credential, and audit controls at the action boundary. The underlying server design should still be reviewed." };
  if (classification === "governance") return { level: "Supported", detail: "Runtime can enforce approved catalog fingerprints and require review when policy-relevant capability metadata changes." };
  if (["input-boundary", "output-boundary", "integrity"].includes(classification)) return { level: "Partial", detail: "Runtime policy can constrain destinations, effects, follow-on actions, or approvals. The server must also correct its schema, output contract, or metadata declaration." };
  if (classification === "readiness") return { level: "Not primary", detail: "This is primarily a server contract, documentation, or interoperability issue. Runtime policy does not replace source-level remediation." };
  return { level: "Not primary", detail: "This control belongs primarily at the MCP endpoint, OAuth provider, network boundary, or operational layer rather than in Runtime policy." };
}

function exampleForRule(rule: Rule) {
  const capability = capabilityForRule(rule).id;
  const classification = rule.classification || "posture";
  const authenticationExamples: Record<string, string> = {
    "OBS-AUTH-001": "An unauthenticated client completes MCP initialization and can enumerate the advertised tool catalog.",
    "OBS-OAUTH-001": "A protected MCP endpoint returns a Bearer challenge, but the client cannot verify protected-resource metadata for the requested resource.",
    "OBS-OAUTH-002": "The protected resource identifies an authorization server whose issuer, endpoints, or discovery document fail secure validation.",
    "OBS-OAUTH-003": "The authorization server offers an authorization-code flow without advertising the S256 PKCE challenge method.",
    "OBS-OAUTH-004": "A new MCP client has neither Dynamic Client Registration nor a Client ID Metadata Document path and must be provisioned manually.",
    "OBS-OAUTH-005": "Protected-resource metadata permits bearer tokens in a query string or request body instead of restricting them to the Authorization header.",
    "OBS-OAUTH-006": "A client can discover the authorization server but cannot determine the minimum MCP scopes needed for read or higher-impact access.",
  };
  if (capability === "authentication") return authenticationExamples[rule.id] || "A client cannot establish a complete, securely bound authentication path from the endpoint's advertised metadata.";
  if (capability === "identity") return "A tool schema includes an api_token, password, or private-key field that would place credential material inside model-visible arguments.";
  if (classification === "capability-chain") return "A catalog combines tools that can read sensitive records with another capability that can transmit data to an external destination.";
  if (classification === "exposure") return "An anonymous or broadly scoped identity receives the same high-impact capability declarations as an administrative identity.";
  if (classification === "policy-opportunity") return "A delete, publish, payment, or administrative tool is advertised without an explicit approval or identity policy boundary.";
  if (classification === "integrity") return "A tool declares itself read-only while its name, description, or input schema indicates that it can modify data.";
  if (classification === "input-boundary") return "A tool accepts a free-form destination URL, file path, command, or query without a declared format, pattern, enum, or constant.";
  if (classification === "output-boundary") return "A web or remote-data tool returns open-world content without a declared output schema before the result re-enters model context.";
  if (capability === "schemas") return "A tool has a vague contract, permits undeclared properties, or exposes unconstrained strings for high-impact inputs.";
  if (capability === "operational") {
    if (rule.id === "OBS-OPS-001") return "Safe metadata requests average more than 500 milliseconds, increasing initialization and timeout risk.";
    if (rule.id === "OBS-TRANSPORT-001") return "A remote MCP endpoint is reachable over plaintext HTTP, exposing metadata and session identifiers to interception or modification.";
    if (rule.id === "OBS-TRANSPORT-002") return "An HTTPS endpoint omits Strict-Transport-Security, leaving first connections more susceptible to downgrade attempts.";
    return "No configured identity can complete MCP initialization, so catalog and readiness evidence cannot be established.";
  }
  if (capability === "governance") return "A previously reviewed tool keeps its name but changes its schema, annotations, fingerprint, or inferred effects in a later assessment.";
  return "Advertised tool metadata is incomplete, contradictory, overly broad, or contains instruction-like language that can influence agent selection.";
}

function runtimeClass(level: RuntimeLevel) { return level.toLowerCase().replace(" ", "-"); }
function humanize(value: string) { return value.replaceAll("-", " ").replace(/\b\w/g, character => character.toUpperCase()); }
