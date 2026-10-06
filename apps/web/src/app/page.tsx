"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import {
  Activity,
  ArrowRight,
  BadgeCheck,
  Braces,
  CheckCircle2,
  CircleGauge,
  ExternalLink,
  FileCheck2,
  FileJson2,
  Fingerprint,
  FlaskConical,
  Globe2,
  KeyRound,
  Layers3,
  LibraryBig,
  LoaderCircle,
  LockKeyhole,
  Radar,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  UserRoundCheck,
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { api } from "@/lib/api";
import type { Assessment, AssessmentSummary, DashboardSummary, OAuthSession } from "@/lib/types";
import { AssessmentStatusBadge, Card } from "@/components/page";

const coverage = [
  {
    icon: Layers3,
    title: "Metadata & catalog",
    detail: "What tools, prompts, and resource descriptions the server advertises.",
  },
  {
    icon: Braces,
    title: "Contracts & schemas",
    detail: "How clearly tools describe their inputs, outputs, and effects.",
  },
  {
    icon: Fingerprint,
    title: "Authentication & identity",
    detail: "Anonymous visibility, authentication signals, and catalog differences between identities.",
  },
  {
    icon: Activity,
    title: "Readiness & next steps",
    detail: "Context estimates, catalog changes, and recommendations to review.",
  },
];

type PublicReportPreview = {
  assessment: Assessment;
  summary: AssessmentSummary;
  name: string;
  host: string;
  authentication: string;
  risk: string;
  official: boolean;
};

const publicPublishers: Record<string, string> = {
  "mcp.linear.app": "Linear",
  "api.githubcopilot.com": "GitHub Copilot",
};

export default function Dashboard() {
  const [data, setData] = useState<DashboardSummary | null>(null);
  const [error, setError] = useState("");
  const [publicReports, setPublicReports] = useState<PublicReportPreview[] | null>(null);

  useEffect(() => {
    api.dashboard().then(setData).catch((requestError) => setError(requestError.message));
  }, []);

  useEffect(() => {
    let active = true;
    api.assessments().then(async ({items}) => {
      const summaries = publicPreviewSummaries(items).slice(0, 3);
      const reports = await Promise.all(summaries.map(async summary => toPublicPreview(summary, await api.assessment(summary.id))));
      if (active) setPublicReports(reports);
    }).catch(() => { if (active) setPublicReports([]); });
    return () => { active = false; };
  }, []);

  return (
    <div className="dashboard-page">
      <section className="dashboard-chapter dashboard-hero" aria-labelledby="dashboard-title">
        <div className="dashboard-chapter-inner">
          <div className="dashboard-hero-copy">
            <div className="dashboard-kicker"><Radar size={14} /> FREE MCP REPORT</div>
            <h1 id="dashboard-title">Understand your MCP server before connecting an AI agent.</h1>
            <p>Get a free report on advertised capabilities, security signals, and tool readiness, with evidence and practical recommendations.</p>
            <QuickAssessmentLauncher />
            <p className="dashboard-scope-note">A metadata review, not a runtime security certification. Reports are visible to everyone with access to this workspace.</p>
          </div>
        </div>
      </section>

      <section className="dashboard-chapter coverage-section" aria-labelledby="coverage-title">
        <div className="dashboard-chapter-inner">
          <div className="dashboard-section-heading">
            <div>
              <div className="section-label">Report contents</div>
              <h2 id="coverage-title">What your report tells you</h2>
            </div>
          </div>
          <div className="coverage-grid">
            {coverage.map(({ icon: Icon, title, detail }) => (
              <article className="coverage-item" key={title}>
                <span><Icon size={17} /></span>
                <div><h3>{title}</h3><p>{detail}</p></div>
              </article>
            ))}
          </div>
        </div>
      </section>

      <PublicIntelligence reports={publicReports}/>

      <section className="dashboard-chapter dashboard-workspace-section" aria-labelledby="workspace-title">
        <div className="dashboard-chapter-inner">
          <div className="dashboard-section-heading dashboard-workspace-heading">
            <div>
              <div className="section-label">Workspace intelligence</div>
              <h2 id="workspace-title">Reports in this workspace</h2>
            </div>
            <p>Review recent assessments and return to their findings and recommendations.</p>
          </div>

          <div className="workspace-proof" aria-labelledby="proof-title">
            <div className="dashboard-subsection-heading">
              <div><div className="section-label">Report activity</div><h3 id="proof-title">Clear signals, kept in context</h3></div>
              <p>Includes live assessments, uploaded metadata, and illustrative examples.</p>
            </div>

            {!data && !error ? (
              <div className="trust-stats" aria-label="Loading report activity" role="status" aria-live="polite" aria-busy="true">
                <span className="sr-only">Loading report activity</span>
                {[1, 2, 3, 4].map((item) => <div className="trust-stat skeleton-stat" key={item}><span className="skeleton" /><strong className="skeleton" /></div>)}
              </div>
            ) : error ? (
              <div className="notice"><ShieldAlert size={16} />{error}. Confirm that the Observatory API is running.</div>
            ) : data && (
              <>
                <div className="trust-stats">
                  <TrustStat label="MCP tools executed" value="0" note="Always" icon={<ShieldCheck size={15} />} featured />
                  <TrustStat label="Assessments started" value={`${data.totalAssessments}`} note="All sources and statuses" icon={<FileCheck2 size={15} />} />
                  <TrustStat label="Assessments completed" value={`${data.completed}`} note="Pipeline completed" icon={<CheckCircle2 size={15} />} />
                  <TrustStat label="Average score" value={`${data.averageScore}/100`} note="Read alongside coverage" icon={<Radar size={15} />} />
                </div>
                <div className="assessment-methods">
                  <span>Report sources</span>
                  <div><Globe2 size={14} /><strong>{data.modes?.live ?? 0}</strong> Server connections</div>
                  <div><FileJson2 size={14} /><strong>{data.modes?.offline ?? 0}</strong> Uploaded metadata</div>
                  <div><FlaskConical size={14} /><strong>{data.modes?.sample ?? 0}</strong> Guided examples</div>
                </div>
              </>
            )}
          </div>

          {data && (
            <div className="history-section" aria-labelledby="history-title">
            <Card
              title="Report history"
              description="Return to a previous MCP report or check an assessment in progress."
              action={<Link href="/assessments" className="button ghost">View all <ArrowRight size={13} /></Link>}
            >
              {data.recent.length ? (
                <div className="table-wrap">
                  <table>
                    <thead><tr><th>Target</th><th>Source</th><th>Status</th><th>Score</th><th>Started</th></tr></thead>
                    <tbody>
                      {data.recent.map((item) => {
                        const assessed = ["completed", "partial"].includes(item.status) && !["authentication-required", "connection-failed"].includes(item.connectionStatus);
                        return (
                          <tr key={item.id}>
                            <td><Link href={`/assessments/${item.id}`} className="target-cell"><strong>{item.target.host || item.target.url}</strong></Link></td>
                            <td><AssessmentSource mode={item.mode} /></td>
                            <td><AssessmentStatusBadge status={item.status} connectionStatus={item.connectionStatus} /></td>
                            <td>{assessed ? <div className="score-inline">{item.overallScore}<div className="mini-progress"><span style={{ width: `${item.overallScore}%` }} /></div></div> : <span className="muted">Not assessed</span>}</td>
                            <td className="history-time">{formatDistanceToNow(new Date(item.createdAt), { addSuffix: true })}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="history-empty">
                  <Radar size={21} />
                  <div><strong>No reports yet</strong><span>Your MCP assessments will appear here as you create them.</span></div>
                  <Link href="/assessments/new" className="button primary">Generate your MCP report <ArrowRight size={13} /></Link>
                </div>
              )}
            </Card>
            </div>
          )}

          <div className="runtime-context">
            <span><Sparkles size={17} /></span>
            <div>
              <div className="section-label">Understanding the findings</div>
              <h3>Start with the evidence and recommended next steps.</h3>
              <p>Policy previews illustrate possible controls. They do not change or enforce policy on your server.</p>
            </div>
            <Link className="button ghost" href="/rules">View report criteria <ArrowRight size={13} /></Link>
          </div>
        </div>
      </section>
    </div>
  );
}

function PublicIntelligence({reports}:{reports:PublicReportPreview[] | null}) {
  return <section className="dashboard-chapter dashboard-public-intelligence" aria-labelledby="public-intelligence-title">
    <div className="dashboard-chapter-inner">
      <div className="dashboard-section-heading compact">
        <div>
          <div className="section-label">Workspace reports</div>
          <h2 id="public-intelligence-title">Explore recent live reports</h2>
        </div>
        <Link className="button ghost" href="/directory">Browse MCP reports <ArrowRight size={13}/></Link>
      </div>
      {reports === null ? <div className="public-intelligence-grid" role="status" aria-live="polite" aria-busy="true"><span className="sr-only">Loading public MCP reports</span>{[1,2,3].map(item=><div className="public-intelligence-card skeleton-public-card" aria-hidden="true" key={item}><span className="skeleton"/><span className="skeleton"/><span className="skeleton"/></div>)}</div> : reports.length === 0 ? <div className="public-intelligence-empty"><LibraryBig size={18}/><span>Live MCP reports will appear here after a server connects and its assessment finishes.</span><Link href="/directory">Open directory</Link></div> : <div className="public-intelligence-grid" aria-label="Live MCP reports in this workspace">{reports.map(report=><PublicIntelligenceCard report={report} key={report.summary.id}/>)}</div>}
    </div>
  </section>;
}

function PublicIntelligenceCard({report}:{report:PublicReportPreview}) {
  const score = report.assessment.scorecard.overall;
  return <Link className="public-intelligence-card" href={`/reports/${report.summary.id}`} aria-label={`Open the MCP report for ${report.name}`}>
    <div className="public-intelligence-header">
      <span className="public-server-mark">{serverInitials(report.name)}</span>
      <div><strong>{report.name}</strong><span>{report.host}</span></div>
      {report.official && <span className="public-official-badge"><BadgeCheck size={12}/>Official</span>}
    </div>
    <dl className="public-intelligence-posture">
      <div><dt><CircleGauge size={12}/>Overall score</dt><dd>{score}<span>/100</span></dd></div>
      <div><dt><KeyRound size={12}/>Authentication</dt><dd>{report.authentication}</dd></div>
      <div><dt><ShieldCheck size={12}/>Observed risk</dt><dd><span className={`public-risk ${report.risk.toLowerCase()}`}>{report.risk}</span></dd></div>
    </dl>
    <div className="public-intelligence-footer"><span>Assessed {formatDistanceToNow(new Date(report.summary.createdAt), {addSuffix:true})}</span><strong>View report <ArrowRight size={12}/></strong></div>
  </Link>;
}

function publicPreviewSummaries(items: AssessmentSummary[]) {
  const latestByTarget = new Map<string, AssessmentSummary>();
  items.filter(item => item.mode === "live" && ["completed","partial"].includes(item.status) && item.connectionStatus === "connected").forEach(item => {
    const key = item.target.url.toLowerCase().replace(/\/$/, "");
    const current = latestByTarget.get(key);
    if (!current || Date.parse(item.createdAt) > Date.parse(current.createdAt)) latestByTarget.set(key,item);
  });
  return [...latestByTarget.values()].sort((left,right) => {
    const leftHost = left.target.host || safeHost(left.target.url);
    const rightHost = right.target.host || safeHost(right.target.url);
    const officialDifference = Number(Boolean(publicPublishers[rightHost])) - Number(Boolean(publicPublishers[leftHost]));
    if (officialDifference) return officialDifference;
    const remoteDifference = Number(isLocalTarget(left.target.url)) - Number(isLocalTarget(right.target.url));
    return remoteDifference || Date.parse(right.createdAt) - Date.parse(left.createdAt);
  });
}

function toPublicPreview(summary:AssessmentSummary,assessment:Assessment):PublicReportPreview {
  const host = summary.target.host || safeHost(summary.target.url);
  return {assessment,summary,host,name:publicPublishers[host] || assessment.server.name || humanizeHost(host),authentication:publicAuthentication(assessment),risk:publicRisk(assessment),official:Boolean(publicPublishers[host])};
}

function publicAuthentication(assessment:Assessment) {
  const value = assessment.server.authentication?.toLowerCase() || "";
  if (assessment.oauth.authorizationCompleted || assessment.oauth.authorizationServerMetadataValid || value.includes("oauth")) return "OAuth";
  if (value.includes("bearer") || value.includes("token")) return "Bearer Token";
  if (value.includes("header") || value.includes("api-key") || value.includes("api key")) return "Custom Headers";
  if (!assessment.oauth.protected && ["none","anonymous","optional"].some(item=>value.includes(item))) return "Anonymous";
  return "Not assessed";
}

function publicRisk(assessment:Assessment) { if (assessment.risk.critical) return "Critical"; if (assessment.risk.high) return "High"; if (assessment.risk.medium) return "Moderate"; return "Low"; }
function safeHost(value:string) { try { return new URL(value).hostname; } catch { return value; } }
function isLocalTarget(value:string) { const host=safeHost(value).toLowerCase(); return host === "localhost" || host === "127.0.0.1" || host === "host.docker.internal" || host.endsWith(".local"); }
function humanizeHost(host:string) { return host.replace(/^mcp\./,"").replace(/^api\./,"").split(".")[0].replace(/[-_]/g," ").replace(/\b\w/g,character=>character.toUpperCase()); }
function serverInitials(name:string) { return name.split(/\s+/).slice(0,2).map(part=>part[0]).join("").toUpperCase(); }

type QuickAssessmentPhase = "idle" | "checking" | "authentication" | "oauth" | "error";

function QuickAssessmentLauncher() {
  const router = useRouter();
  const attempt = useRef(0);
  const [url, setURL] = useState("");
  const [phase, setPhase] = useState<QuickAssessmentPhase>("idle");
  const [authMethod, setAuthMethod] = useState<"token" | "oauth">("token");
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [oauthSession, setOAuthSession] = useState<OAuthSession | null>(null);

  useEffect(() => () => { attempt.current += 1; }, []);

  const resetForURL = (nextURL: string) => {
    attempt.current += 1;
    setURL(nextURL);
    setPhase("idle");
    setToken("");
    setError("");
    setOAuthSession(null);
  };

  const watchConnection = async (assessmentId: string, attemptID: number, authenticated: boolean) => {
    for (let check = 0; check < 30; check += 1) {
      await new Promise(resolve => setTimeout(resolve, 700));
      if (attempt.current !== attemptID) return;
      const assessment = await api.assessment(assessmentId);
      if (attempt.current !== attemptID) return;
      const settled = ["completed", "partial", "failed", "canceled"].includes(assessment.status);
      if (assessment.connectionStatus === "connected") {
        router.push(`/assessments/${assessmentId}`);
        return;
      }
      if (settled && assessment.connectionStatus === "authentication-required") {
        setPhase("authentication");
        setError(authenticated ? "That credential did not establish access. Check it or try another sign-in method." : "");
        return;
      }
      if (settled && assessment.connectionStatus === "connection-failed") {
        setPhase("error");
        setError(connectionMessage(assessment));
        return;
      }
      if (["completed", "partial"].includes(assessment.status)) {
        router.push(`/assessments/${assessmentId}`);
        return;
      }
      if (["failed", "canceled"].includes(assessment.status)) {
        setPhase("error");
        setError(connectionMessage(assessment));
        return;
      }
    }
    router.push(`/assessments/${assessmentId}`);
  };

  const queueAssessment = async (credential?: { bearerToken?: string; oauthSessionId?: string }) => {
    const attemptID = attempt.current + 1;
    attempt.current = attemptID;
    setPhase("checking");
    setError("");
    try {
      const credentialProfiles = credential ? [{
        label: "Authenticated access",
        bearerToken: credential.bearerToken,
        oauthSessionId: credential.oauthSessionId,
      }] : undefined;
      const result = await api.create({mode:"live", target:{protocol:"mcp", url:url.trim()}, credentialProfiles});
      await watchConnection(result.assessmentId, attemptID, Boolean(credential));
    } catch (cause) {
      if (attempt.current !== attemptID) return;
      setPhase(credential ? "authentication" : "error");
      setError(cause instanceof Error ? cause.message : "Report generation could not be started.");
    }
  };

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    if (phase === "authentication") {
      if (authMethod === "token" && token.trim()) void queueAssessment({bearerToken:token.trim()});
      return;
    }
    void queueAssessment();
  };

  const connectOAuth = async () => {
    const oauthAttempt = attempt.current + 1;
    attempt.current = oauthAttempt;
    const popup = window.open("about:blank", "observatory-quick-oauth", "popup,width=620,height=760");
    setPhase("oauth");
    setError("");
    try {
      let session = await api.startOAuth(url.trim(), "Authenticated access");
      setOAuthSession(session);
      if (session.status === "not-required") {
        popup?.close();
        await queueAssessment();
        return;
      }
      if (!session.authorizationUrl) throw new Error(session.error || "This endpoint did not provide a usable OAuth authorization path.");
      if (popup) popup.location.href = session.authorizationUrl;
      else window.open(session.authorizationUrl, "_blank", "noopener,noreferrer");
      const expiresAt = new Date(session.expiresAt).getTime();
      while (Date.now() < expiresAt) {
        await new Promise(resolve => setTimeout(resolve, 1200));
        if (attempt.current !== oauthAttempt) { popup?.close(); return; }
        session = await api.oauthSession(session.id);
        if (attempt.current !== oauthAttempt) { popup?.close(); return; }
        setOAuthSession(session);
        if (session.status === "authorized") {
          popup?.close();
          await queueAssessment({oauthSessionId:session.id});
          return;
        }
        if (["failed", "denied", "expired", "canceled", "unsupported"].includes(session.status)) {
          throw new Error(session.error || `OAuth authorization ${session.status}.`);
        }
      }
      throw new Error("OAuth authorization expired.");
    } catch (cause) {
      popup?.close();
      setPhase("authentication");
      setError(cause instanceof Error ? cause.message : "OAuth connection failed.");
    }
  };

  const busy = phase === "checking" || phase === "oauth";
  return <form className="dashboard-assessment-launcher" onSubmit={submit} aria-label="Generate your MCP report">
    <div className="dashboard-launcher-heading">
      <span><Globe2 size={17}/></span>
      <div><strong>Generate your MCP report</strong><small>Enter the server’s Streamable HTTP endpoint. Add access details if it requires authentication.</small></div>
    </div>
    <label htmlFor="dashboard-mcp-url">MCP Server URL</label>
    <div className="dashboard-url-row">
      <span aria-hidden="true"><Globe2 size={17}/></span>
      <input id="dashboard-mcp-url" className="input" required type="url" placeholder="https://mcp.example.com/mcp" value={url} onChange={event=>resetForURL(event.target.value)}/>
      {phase !== "authentication" && <button className="button primary dashboard-primary-cta" disabled={busy || !url.trim()} aria-busy={busy}>
        {busy ? <><LoaderCircle className="animate-spin" size={15}/>{phase === "oauth" ? "Waiting for sign-in…" : "Checking access…"}</> : <>Generate your MCP report <ArrowRight size={15}/></>}
      </button>}
    </div>
    <div className="dashboard-launcher-assurance"><ShieldCheck size={13}/><span>We inspect advertised metadata. We never execute your tools.</span></div>

    {phase === "checking" && <div className="dashboard-launcher-status" role="status" aria-live="polite"><LoaderCircle className="animate-spin" size={16}/><span><strong>Connecting safely</strong>Checking whether the endpoint exposes metadata anonymously.</span></div>}

    {phase === "authentication" && <div className="dashboard-auth-step" aria-live="polite">
      <div className="dashboard-auth-heading"><KeyRound size={17}/><span><strong>This endpoint requires authentication</strong>Choose an access method to continue generating your MCP report.</span></div>
      <div className="dashboard-auth-methods" role="tablist" aria-label="Authentication method">
        <button type="button" role="tab" aria-selected={authMethod === "token"} className={authMethod === "token" ? "active" : ""} onClick={()=>{setAuthMethod("token");setError("")}}><KeyRound size={14}/>Bearer token</button>
        <button type="button" role="tab" aria-selected={authMethod === "oauth"} className={authMethod === "oauth" ? "active" : ""} onClick={()=>{setAuthMethod("oauth");setError("")}}><UserRoundCheck size={14}/>OAuth</button>
      </div>
      {error && <div className="dashboard-launcher-error" role="alert"><ShieldAlert size={14}/>{error}</div>}
      {authMethod === "token" ? <div className="dashboard-token-row" role="tabpanel">
        <input aria-label="Bearer token" className="input" required type="password" autoComplete="off" placeholder="Paste bearer token" value={token} onChange={event=>setToken(event.target.value)}/>
        <button className="button primary" disabled={!token.trim()}>Generate your MCP report <ArrowRight size={14}/></button>
      </div> : <div className="dashboard-oauth-row" role="tabpanel">
        <span>{oauthSession?.error || "Sign in on the server's authorization page, then report generation continues automatically."}</span>
        <button type="button" className="button primary" onClick={()=>void connectOAuth()}><ExternalLink size={14}/>Connect with OAuth</button>
      </div>}
      <div className="dashboard-auth-footer"><LockKeyhole size={12}/>Use credentials scoped to this server. Access details are encrypted for the assessment.</div>
    </div>}

    {phase === "error" && <div className="dashboard-launcher-error dashboard-launcher-error-block" role="alert"><ShieldAlert size={15}/><span><strong>We could not connect to that endpoint.</strong>{error}</span><button type="button" className="button" onClick={()=>void queueAssessment()}>Try again</button></div>}
    <div className="dashboard-launcher-advanced"><Link href={`/assessments/new${url ? `?target=${encodeURIComponent(url)}` : ""}`}>Upload metadata or compare identities</Link> · Includes custom headers</div>
  </form>;
}

function connectionMessage(assessment: Assessment) {
  return assessment.error || "Check that the URL is a reachable Streamable HTTP MCP endpoint and try again.";
}

function TrustStat({ label, value, note, icon, featured = false }: { label: string; value: string; note: string; icon: React.ReactNode; featured?: boolean }) {
  return <div className={`trust-stat ${featured ? "featured" : ""}`}><div>{icon}{label}</div><strong>{value}</strong><span>{note}</span></div>;
}

function AssessmentSource({ mode }: { mode: string }) {
  const labels: Record<string, string> = { live: "Server", offline: "Upload", sample: "Example" };
  return <span className={`badge ${mode}`}>{labels[mode] || mode}</span>;
}
