"use client";

import { use, useEffect, useState } from "react";
import Link from "next/link";
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  Boxes,
  Braces,
  CheckCircle2,
  CircleDashed,
  Download,
  Fingerprint,
  Gauge,
  GitBranch,
  KeyRound,
  LockKeyhole,
  Printer,
  ShieldCheck,
  Users,
} from "lucide-react";
import { api, artifactURL } from "@/lib/api";
import type { Assessment, Finding } from "@/lib/types";
import { PageHeading, Score, StatusBadge } from "@/components/page";

type Recommendation = Assessment["recommendations"][number];
type Applicability = { level: "Yes" | "Partial" | "No"; detail: string };

export default function Report({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [assessment, setAssessment] = useState<Assessment | null>(null);
  const [error, setError] = useState("");

  useEffect(() => { api.assessment(id).then(setAssessment).catch(cause => setError(cause instanceof Error ? cause.message : "Unable to load this report.")); }, [id]);

  if (error) return <div className="state-panel card danger" role="alert"><AlertTriangle size={22}/><div><strong>Report could not be loaded</strong><span>{error}</span></div></div>;
  if (!assessment) return <div className="card report-loading" role="status" aria-live="polite" aria-busy="true"><span className="skeleton" aria-hidden="true"/><div><strong>Preparing assessment report</strong><p>Organizing the latest evidence and recommendations.</p></div></div>;

  const a = assessment;
  const band = a.scorecard.coverage < 70
    ? { label: "Limited evidence", tone: "developing", summary: "The score reflects assessed declarations. Missing evidence and runtime behavior still need verification." }
    : scoreBand(a.scorecard.overall);
  const strengths = reportStrengths(a);
  const priorityFindings = [...a.findings].sort((left, right) => severityRank(left.severity) - severityRank(right.severity)).filter(finding => ["critical", "high"].includes(finding.severity));
  const displayedPriorityFindings = priorityFindings.length ? priorityFindings.slice(0, 5) : [...a.findings].sort((left, right) => severityRank(left.severity) - severityRank(right.severity)).slice(0, 3);
  const operational = dimension(a, "operational");
  const protocol = dimension(a, "protocol");
  const connectedProfiles = a.identityExposure.profiles.filter(profile => profile.status === "connected");
  const accessDifferences = a.identityExposure.tools.filter(tool => tool.hiddenFrom.length > 0).length;
  const contractGaps = a.readiness.tools.filter(tool => tool.score < 70).length;
  const policyFindings = a.findings.filter(finding => ["policy-opportunity", "capability-chain", "credential-boundary", "exposure"].includes(finding.classification));
  const mutatingTools = a.tools.filter(tool => tool.classification.isMutating).length;

  return <div className="consultant-report">
    <PageHeading
      eyebrow="Free MCP Report"
      title={a.server.name || a.target.host || "MCP Assessment Report"}
      description={`${a.target.url} · ${Math.round(a.scorecard.coverage)}% evidence coverage`}
      actions={<><button className="button report-print-button" onClick={() => window.print()}><Printer size={13}/>Print</button><Link href={`/assessments/${id}`} className="button"><ArrowLeft size={13}/>Assessment details</Link></>}
    />

    <div className="report-assurance"><ShieldCheck size={15}/><span><strong>Assessment boundary:</strong> metadata and declared contracts only. No MCP tools were executed, no prompts were sent, and no payload fuzzing occurred.</span></div>

    <section className="card consultant-section executive-section" aria-labelledby="executive-summary-title">
      <ReportSectionHeading number="01" eyebrow="Executive Summary" title="Executive Summary" id="executive-summary-title"/>
      <div className="executive-summary-layout">
        <div className="executive-judgement"><span className={`readiness-band ${band.tone}`}>{band.label}</span><h2>{a.executiveSummary || `${a.server.name || a.target.host} achieved a readiness score of ${a.scorecard.overall}/100.`}</h2><p>{executiveInterpretation(a)}</p></div>
        <dl className="report-scope">
          <div><dt>Assessment type</dt><dd>{a.mode === "offline" ? "Uploaded metadata" : a.mode === "sample" ? "Guided example" : "Live metadata assessment"}</dd></div>
          <div><dt>Connection</dt><dd>{plainLabel(a.connectionStatus)}</dd></div>
          <div><dt>MCP protocol</dt><dd>{a.server.protocolVersion || "Not observed"}</dd></div>
          <div><dt>Catalog reviewed</dt><dd>{a.server.toolCount} tools</dd></div>
          <div><dt>Evidence coverage</dt><dd>{Math.round(a.scorecard.coverage)}%</dd></div>
          <div><dt>Tools executed</dt><dd>None</dd></div>
        </dl>
      </div>
    </section>

    <section className="card consultant-section" aria-labelledby="overall-score-title">
      <ReportSectionHeading number="02" eyebrow="Overall Readiness Score" title="Overall Readiness Score" id="overall-score-title"/>
      <div className="overall-score-layout">
        <div className="overall-score-summary"><Score value={a.scorecard.overall}/><div><span className={`readiness-band ${band.tone}`}>{band.label}</span><h3>{band.summary}</h3><p>The score combines observed posture with confidence-adjusted metadata evidence. Coverage indicates how much of the assessment could be supported by available evidence.</p></div></div>
        <div className="report-dimensions">{Object.values(a.scorecard.dimensions).map(item => <div key={item.name}><div><strong>{item.name}</strong><span>{item.score}/100</span></div><div className="mini-progress"><span style={{ width: `${item.score}%` }}/></div><small>{Math.round(item.coverage)}% evidence coverage · {plainLabel(item.status)}</small></div>)}</div>
      </div>
    </section>

    <section className="card consultant-section" aria-labelledby="strengths-title">
      <ReportSectionHeading number="03" eyebrow="Confirmed strengths" title="Strengths" id="strengths-title"/>
      {strengths.length ? <div className="report-strengths">{strengths.map(strength => <article key={strength.title}><span><CheckCircle2 size={16}/></span><div><h3>{strength.title}</h3><p>{strength.detail}</p></div></article>)}</div> : <div className="report-empty"><CircleDashed size={18}/><span><strong>No material strength was confirmed.</strong>Available evidence was insufficient to identify a high-confidence strength.</span></div>}
    </section>

    <section className="card consultant-section" aria-labelledby="priority-findings-title">
      <ReportSectionHeading number="04" eyebrow="Issues requiring attention" title="Priority Findings" id="priority-findings-title" aside={`${priorityFindings.length} critical or high`}/>
      {displayedPriorityFindings.length ? <div className="priority-finding-list">{displayedPriorityFindings.map((finding, index) => <article key={finding.id}><span className="finding-number">{String(index + 1).padStart(2, "0")}</span><div><div className="finding-title-line"><StatusBadge value={finding.severity}/><h3>{finding.title}</h3></div><p>{finding.description}</p><div className="finding-impact"><strong>Why it matters</strong><span>{finding.whyItMatters}</span></div></div></article>)}</div> : <div className="report-empty"><ShieldCheck size={18}/><span><strong>No priority finding was produced.</strong>No critical or high-severity rule matched the available evidence.</span></div>}
    </section>

    <section className="card consultant-section domain-section" aria-labelledby="authentication-title">
      <ReportSectionHeading number="05" eyebrow="Control domain" title="Authentication" id="authentication-title" icon={<KeyRound size={17}/>}/>
      <div className="domain-summary-grid">
        <DomainMetric label="Endpoint access" value={a.oauth.protected || a.server.authentication === "required" ? "Protected" : "Anonymous observed"}/>
        <DomainMetric label="OAuth metadata" value={a.oauth.resourceMetadataValid && a.oauth.authorizationServerMetadataValid ? "Validated" : "Incomplete or unavailable"}/>
        <DomainMetric label="PKCE S256" value={a.oauth.pkceS256 ? "Advertised" : "Not observed"}/>
        <DomainMetric label="Bearer transport" value={a.oauth.headerBearerSupported ? "Authorization header" : "Not confirmed"}/>
      </div>
      <DomainNarrative icon={<ShieldCheck size={15}/>} title="Assessment judgement" text={authenticationNarrative(a)}/>
      <p className="domain-boundary">Authentication metadata and session establishment were assessed. Enforcement of authorization on individual tool calls was not tested.</p>
    </section>

    <section className="card consultant-section domain-section" aria-labelledby="catalog-quality-title">
      <ReportSectionHeading number="06" eyebrow="Control domain" title="Catalog Quality" id="catalog-quality-title" icon={<Boxes size={17}/>}/>
      <div className="domain-summary-grid">
        <DomainMetric label="Advertised tools" value={String(a.tools.length)}/>
        <DomainMetric label="Average contract readiness" value={`${Math.round(a.readiness.averageScore || 0)}/100`}/>
        <DomainMetric label="Contracts below 70" value={String(contractGaps)}/>
        <DomainMetric label="Metadata integrity signals" value={String(a.contentIntegrity.signals.length)}/>
      </div>
      <DomainNarrative icon={<Braces size={15}/>} title="Assessment judgement" text={catalogNarrative(a, contractGaps)}/>
      <p className="domain-boundary">Catalog scores measure declaration quality, not runtime correctness, reliability, rollback behavior, or tool authorization.</p>
    </section>

    <section className="card consultant-section domain-section" aria-labelledby="identity-analysis-title">
      <ReportSectionHeading number="07" eyebrow="Control domain" title="Identity Analysis" id="identity-analysis-title" icon={<Fingerprint size={17}/>}/>
      <div className="identity-report-summary"><div><strong>{connectedProfiles.length}</strong><span>connected profiles</span></div><div><strong>{a.identityExposure.anonymousToolCount}</strong><span>tools advertised anonymously</span></div><div><strong>{a.identityExposure.comparedProfiles >= 2 ? accessDifferences : "—"}</strong><span>catalog access differences</span></div></div>
      {a.identityExposure.profiles.length ? <div className="identity-report-list">{a.identityExposure.profiles.map(profile => <div key={profile.id}><span className="identity-report-icon"><Users size={14}/></span><div><strong>{profile.label}</strong><small>{plainLabel(profile.authentication)}</small></div><b>{profile.status === "connected" ? `${profile.toolCount} tools advertised` : plainLabel(profile.status)}</b></div>)}</div> : <div className="report-empty"><Users size={18}/><span><strong>No identity profile was available.</strong>Catalog-level privilege separation could not be evaluated.</span></div>}
      <DomainNarrative icon={<LockKeyhole size={15}/>} title="Assessment judgement" text={identityNarrative(a, connectedProfiles.length, accessDifferences)}/>
      <p className="domain-boundary">Identity analysis compares catalog visibility in isolated sessions. Visibility does not prove permission to execute a tool.</p>
    </section>

    <section className="card consultant-section domain-section" aria-labelledby="policy-readiness-title">
      <ReportSectionHeading number="08" eyebrow="Control domain" title="Policy Readiness" id="policy-readiness-title" icon={<GitBranch size={17}/>}/>
      <div className="domain-summary-grid">
        <DomainMetric label="Change-capable tools" value={String(mutatingTools)}/>
        <DomainMetric label="Policy-related findings" value={String(policyFindings.length)}/>
        <DomainMetric label="Capability chains" value={String(a.riskChains.length)}/>
        <DomainMetric label="Policy preview" value={a.policySimulation.generated ? "Available" : "Not generated"}/>
      </div>
      <DomainNarrative icon={<ShieldCheck size={15}/>} title="Assessment judgement" text={policyNarrative(a, mutatingTools, policyFindings.length)}/>
      <p className="domain-boundary">Policy outcomes shown in the assessment are illustrative. No AgntID Runtime policy was deployed or enforced during this assessment.</p>
    </section>

    <section className="card consultant-section domain-section" aria-labelledby="operational-maturity-title">
      <ReportSectionHeading number="09" eyebrow="Control domain" title="Operational Maturity" id="operational-maturity-title" icon={<Activity size={17}/>}/>
      <div className="domain-summary-grid">
        <DomainMetric label="Operational score" value={operational ? `${operational.score}/100` : "Not assessed"}/>
        <DomainMetric label="Protocol score" value={protocol ? `${protocol.score}/100` : "Not assessed"}/>
        <DomainMetric label="Catalog baseline" value={a.catalogDrift.compared ? (a.catalogDrift.stable ? "Stable" : `${a.catalogDrift.added + a.catalogDrift.removed + a.catalogDrift.modified} changes`) : "Not established"}/>
        <DomainMetric label="Report artifacts" value={String(a.artifacts.length)}/>
      </div>
      <DomainNarrative icon={<Gauge size={15}/>} title="Assessment judgement" text={operationalNarrative(a, operational?.score)}/>
      <p className="domain-boundary">Operational maturity is based on observable endpoint, protocol, metadata, and drift signals. Runtime reliability and recovery behavior require execution evidence.</p>
    </section>

    <section className="card consultant-section recommendations-section" aria-labelledby="recommendations-title">
      <ReportSectionHeading number="10" eyebrow="Prioritized remediation plan" title="Recommendations" id="recommendations-title" aside={`${a.recommendations.length} recommendations`}/>
      <p className="recommendations-intro">Start with these evidence-based recommendations. Optional policy previews explain possible controls; they do not replace fixes to the server.</p>
      {a.recommendations.length ? <div className="consultant-recommendations">{[...a.recommendations].sort((left, right) => severityRank(left.priority) - severityRank(right.priority)).map((recommendation, index) => <RecommendationRow key={recommendation.id} number={index + 1} recommendation={recommendation} finding={findingForRecommendation(a, recommendation)}/>)}</div> : <div className="report-empty"><CheckCircle2 size={18}/><span><strong>No recommendation was generated.</strong>The available evidence did not produce a rule-backed remediation item.</span></div>}
    </section>

    <section className="card report-downloads"><div><div className="section-label">Report artifacts</div><h2>Downloadable report set</h2><p>Executive, technical, and machine-readable formats share the same canonical assessment evidence.</p></div><div className="toolbar">{a.artifacts.map(file => <a key={file.id} className="button" href={artifactURL(a.id, file.id)}><Download size={13}/>{file.name}</a>)}</div></section>
  </div>;
}

function ReportSectionHeading({ number, eyebrow, title, id, aside, icon }: { number: string; eyebrow: string; title: string; id: string; aside?: string; icon?: React.ReactNode }) {
  return <header className="consultant-section-heading"><span>{icon || number}</span><div><div className="section-label">{eyebrow}</div><h2 id={id}>{title}</h2></div>{aside && <small>{aside}</small>}</header>;
}

function DomainMetric({ label, value }: { label: string; value: string }) {
  return <div className="domain-metric"><span>{label}</span><strong>{value}</strong></div>;
}

function DomainNarrative({ icon, title, text }: { icon: React.ReactNode; title: string; text: string }) {
  return <div className="domain-narrative"><span>{icon}</span><div><strong>{title}</strong><p>{text}</p></div></div>;
}

function RecommendationRow({ number, recommendation, finding }: { number: number; recommendation: Recommendation; finding?: Finding }) {
  const applicability = agentIDApplicability(finding);
  return <article className="consultant-recommendation"><header><span>{String(number).padStart(2, "0")}</span><div><StatusBadge value={recommendation.priority}/><h3>{recommendation.title}</h3></div><small>{recommendation.effort ? `${plainLabel(recommendation.effort)} effort` : "Effort not estimated"}</small></header><dl>
    <div><dt>Current State</dt><dd>{finding?.description || recommendation.title}</dd></div>
    <div><dt>Risk</dt><dd>{finding?.whyItMatters || "The finding may reduce confidence in the server's readiness for governed agent use."}</dd></div>
    <div><dt>Recommendation</dt><dd>{recommendation.detail}</dd></div>
    </dl><details className="agentid-applicability policy-preview-details"><summary>Optional AgntID policy preview</summary><p><span className={`applicability-badge ${applicability.level.toLowerCase()}`}>{applicability.level}</span>{applicability.detail}</p><p className="muted">Illustrative only. No policy was deployed or enforced.</p></details></article>;
}

function scoreBand(score: number) {
  if (score >= 85) return { label: "Few observed gaps", tone: "strong", summary: "The assessed declarations produced few score penalties. Runtime behavior remains unverified." };
  if (score >= 70) return { label: "Developing", tone: "developing", summary: "The core posture is established, but material gaps should be addressed before broader use." };
  if (score >= 50) return { label: "Needs focused improvement", tone: "needs", summary: "Several readiness domains require remediation and additional evidence." };
  return { label: "Foundational gaps", tone: "needs", summary: "The observed posture requires foundational improvements before governed production use." };
}

function reportStrengths(a: Assessment) {
  const items: Array<{ title: string; detail: string }> = Object.values(a.scorecard.dimensions).filter(item => item.score >= 85 && item.coverage >= 70).map(item => ({ title: `${item.name} posture`, detail: `${item.score}/100 with ${Math.round(item.coverage)}% evidence coverage.` }));
  if (a.oauth.protected && a.oauth.resourceMetadataValid && a.oauth.authorizationServerMetadataValid && a.oauth.pkceS256) items.push({ title: "OAuth discovery controls", detail: "Protected-resource and authorization-server metadata were validated, with PKCE S256 advertised." });
  if (a.server.tls === "valid") items.push({ title: "Transport protection", detail: "A valid TLS connection was observed for the assessed endpoint." });
  return items.slice(0, 4);
}

function executiveInterpretation(a: Assessment) {
  const priority = a.risk.critical + a.risk.high;
  if (priority > 0) return `${priority} priority ${priority === 1 ? "finding requires" : "findings require"} attention. The report separates observed controls from areas that remain unverified without tool execution.`;
  return "No critical or high-severity rule matched the available evidence. Lower-severity findings and unassessed runtime behavior should still be reviewed in context.";
}

function authenticationNarrative(a: Assessment) {
  if (a.mode === "offline" || ["not-assessed", "unavailable"].includes(a.oauth.status)) return "Authentication was not established by this assessment. Imported declarations and unavailable probes do not prove anonymous access.";
  if (a.mode === "sample") return "Authentication information in this report is illustrative sample data, not a live observation.";
  if (a.oauth.protected && a.oauth.resourceMetadataValid && a.oauth.authorizationServerMetadataValid && a.oauth.pkceS256) return "The endpoint presents a coherent OAuth discovery posture and advertises PKCE S256. Review scopes and identity-specific authorization separately because tool-call enforcement was outside this assessment boundary.";
  if (a.oauth.protected) return "Authentication is required, but one or more expected OAuth discovery or PKCE signals were not confirmed. Review the detailed finding and endpoint configuration.";
  if (a.connectionStatus !== "connected") return "No identity established an MCP session. Authentication and catalog visibility need further verification.";
  return "An MCP session was established. Review the identity exposure evidence to determine whether anonymous access was observed and intentional.";
}

function catalogNarrative(a: Assessment, gaps: number) {
  if (!a.tools.length) return "No tool catalog was available, so catalog quality could not be assessed.";
  if (!gaps && a.readiness.averageScore >= 85) return `The ${a.tools.length}-tool catalog has strong observed declaration quality, with an average contract readiness score of ${Math.round(a.readiness.averageScore)}/100.`;
  return `${gaps} of ${a.readiness.tools.length || a.tools.length} assessed tool contracts scored below 70. Prioritize recurring schema, annotation, and output-contract gaps before relying on precise automated policy.`;
}

function identityNarrative(a: Assessment, connected: number, differences: number) {
  if (a.identityExposure.comparedProfiles < 2) return `${connected} identity profile connected successfully. At least two connected identities are required to evaluate catalog-level privilege separation.`;
  if (differences > 0) return `${differences} tool catalog entries differed across connected identities, providing evidence that visibility changes with access context.`;
  return "Connected identities received equivalent advertised catalogs. Confirm whether this matches the intended least-privilege model.";
}

function policyNarrative(a: Assessment, mutating: number, findings: number) {
  if (!a.tools.length) return "Policy readiness could not be evaluated because no catalog was available.";
  if (findings > 0) return `${mutating} advertised tools were classified as change-capable and ${findings} policy-related findings were produced. Define explicit identity, effect, destination, and approval controls before governed use.`;
  return `The catalog contains ${mutating} change-capable tools and no dedicated policy finding. Continue to document allow, deny, and approval expectations for sensitive capabilities.`;
}

function operationalNarrative(a: Assessment, score?: number) {
  if (score === undefined) return "Operational maturity was not assessed from the available evidence.";
  const baseline = a.catalogDrift.compared ? (a.catalogDrift.stable ? "A stable catalog baseline was observed." : "Catalog changes were observed against a prior baseline.") : "No prior catalog baseline was available for comparison.";
  return `The operational dimension scored ${score}/100. ${baseline} Runtime reliability, rollback, and recovery behavior remain outside a metadata-only assessment.`;
}

function findingForRecommendation(a: Assessment, recommendation: Recommendation) {
  return a.findings.find(finding => finding.recommendation?.id === recommendation.id || finding.title === recommendation.title);
}

function agentIDApplicability(finding?: Finding): Applicability {
  if (!finding) return { level: "Partial", detail: "Runtime controls may help, but applicability requires review against the underlying evidence." };
  if (["capability-chain", "policy-opportunity", "credential-boundary", "exposure"].includes(finding.classification)) return { level: "Yes", detail: "Identity-aware allow, deny, approval, and audit policy directly fits this runtime control gap. Server-side design should still be reviewed." };
  if (["input-boundary", "output-boundary", "integrity"].includes(finding.classification)) return { level: "Partial", detail: "Runtime policy can constrain effects or follow-on actions, but the published schema, output contract, or annotations must also be corrected at the server." };
  if (finding.classification === "readiness") return { level: "No", detail: "This is primarily a server contract or schema-quality issue. Runtime policy does not replace source-level remediation." };
  if (finding.classification === "posture") return { level: "No", detail: "This control belongs at the MCP endpoint, network boundary, or TLS termination layer." };
  return { level: "Partial", detail: "Runtime policy may reduce exposure, while the underlying implementation remains the server owner's responsibility." };
}

function dimension(a: Assessment, id: string) {
  return a.scorecard.dimensions[id] || Object.values(a.scorecard.dimensions).find(item => item.name.toLowerCase() === id);
}

function severityRank(value: string) {
  return ({ critical: 0, high: 1, medium: 2, low: 3, info: 4 } as Record<string, number>)[value] ?? 5;
}

function plainLabel(value: string) { return value.replaceAll("-", " "); }
