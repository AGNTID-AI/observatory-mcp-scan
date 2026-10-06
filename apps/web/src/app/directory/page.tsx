"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import {
  ArrowRight,
  BadgeCheck,
  BookOpen,
  Building2,
  Check,
  CircleGauge,
  Globe2,
  KeyRound,
  Laptop,
  LibraryBig,
  Plus,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  Users,
} from "lucide-react";
import { format } from "date-fns";
import { api } from "@/lib/api";
import type { Assessment, AssessmentSummary } from "@/lib/types";
import { PageHeading } from "@/components/page";

type DirectoryEntry = {
  key: string;
  name: string;
  host: string;
  assessment: Assessment;
  summary: AssessmentSummary;
  assessmentCount: number;
  category: string;
  authentication: AuthenticationType;
  risk: RiskLevel;
  official: boolean;
  deployment: "Remote" | "Local";
};

type AuthenticationType = "Anonymous" | "Bearer Token" | "OAuth" | "Custom Headers" | "Not Assessed";
type RiskLevel = "Critical" | "High" | "Moderate" | "Low";

const verifiedPublishers: Record<string, { name: string; category: string }> = {
  "mcp.linear.app": { name: "Linear", category: "Productivity" },
  "api.githubcopilot.com": { name: "GitHub Copilot", category: "Developer Tools" },
};

export default function MCPDirectory() {
  const [entries, setEntries] = useState<DirectoryEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("All");
  const [authentication, setAuthentication] = useState("All");
  const [risk, setRisk] = useState("All");
  const [deployment, setDeployment] = useState("All");
  const [officialOnly, setOfficialOnly] = useState(false);
  const [sort, setSort] = useState("popular");

  useEffect(() => {
    let active = true;
    api.assessments().then(async response => {
      const groups = latestPublicAssessments(response.items);
      const results = await Promise.all(groups.map(async group => {
        try {
          const assessment = await api.assessment(group.latest.id);
          return toDirectoryEntry(group.key, group.latest, group.count, assessment);
        } catch {
          return null;
        }
      }));
      if (active) setEntries(results.filter((entry): entry is DirectoryEntry => entry !== null));
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  const categories = useMemo(() => ["All", ...new Set(entries.map(entry => entry.category))].sort((left, right) => left === "All" ? -1 : right === "All" ? 1 : left.localeCompare(right)), [entries]);
  const filtered = useMemo(() => {
    const matching = entries.filter(entry => {
      const text = `${entry.name} ${entry.host} ${entry.category} ${entry.assessment.executiveSummary || ""}`.toLowerCase();
      return text.includes(query.toLowerCase()) &&
        (category === "All" || entry.category === category) &&
        (authentication === "All" || entry.authentication === authentication) &&
        (risk === "All" || entry.risk === risk) &&
        (deployment === "All" || entry.deployment === deployment) &&
        (!officialOnly || entry.official);
    });
    return matching.sort((left, right) => {
      if (sort === "readiness") return right.assessment.scorecard.overall - left.assessment.scorecard.overall;
      if (sort === "recent") return Date.parse(right.summary.createdAt) - Date.parse(left.summary.createdAt);
      if (sort === "risk") return riskRank(right.risk) - riskRank(left.risk);
      return right.assessmentCount - left.assessmentCount || Date.parse(right.summary.createdAt) - Date.parse(left.summary.createdAt);
    });
  }, [entries, query, category, authentication, risk, deployment, officialOnly, sort]);

  const publicAssessmentCount = entries.reduce((total, entry) => total + entry.assessmentCount, 0);

  return <div className="mcp-directory-page">
    <PageHeading
      eyebrow="Public MCP intelligence"
      title="MCP Directory"
      description="Browse known MCP servers through public readiness evidence, not promotional claims."
      actions={<Link href="/assessments/new" className="button primary"><Plus size={14}/>Assess an MCP server</Link>}
    />

    <section className="directory-intro" aria-label="Directory overview">
      <div className="directory-intro-copy"><span><LibraryBig size={18}/></span><div><strong>Independent readiness context</strong><p>Compare metadata quality, authentication posture, and operational risk before opening the full assessment.</p></div></div>
      <div className="directory-stat"><strong>{entries.length}</strong><span>assessed servers</span></div>
      <div className="directory-stat"><strong>{publicAssessmentCount}</strong><span>public assessments</span></div>
      <div className="directory-stat"><strong>{entries.filter(entry => entry.official).length}</strong><span>verified publishers</span></div>
    </section>

    <section className="directory-controls card" aria-label="Directory filters">
      <div className="directory-search"><Search size={16}/><input className="input" placeholder="Search servers, categories, or capabilities…" value={query} onChange={event => setQuery(event.target.value)}/></div>
      <div className="directory-filter-row">
        <label><span>Authentication</span><select className="select" value={authentication} onChange={event => setAuthentication(event.target.value)}><option>All</option><option>Anonymous</option><option>Bearer Token</option><option>OAuth</option><option>Custom Headers</option><option>Not Assessed</option></select></label>
        <label><span>Risk level</span><select className="select" value={risk} onChange={event => setRisk(event.target.value)}><option>All</option><option>Critical</option><option>High</option><option>Moderate</option><option>Low</option></select></label>
        <label><span>Location</span><select className="select" value={deployment} onChange={event => setDeployment(event.target.value)}><option>All</option><option>Remote</option><option>Local</option></select></label>
        <label><span>Sort by</span><select className="select" value={sort} onChange={event => setSort(event.target.value)}><option value="popular">Most assessed</option><option value="readiness">Highest readiness</option><option value="recent">Latest assessment</option><option value="risk">Highest risk</option></select></label>
        <button className={`directory-official-filter ${officialOnly ? "active" : ""}`} aria-pressed={officialOnly} onClick={() => setOfficialOnly(value => !value)}><BadgeCheck size={15}/><span>Official only</span>{officialOnly && <Check size={13}/>}</button>
      </div>
      <div className="directory-categories" aria-label="Categories">{categories.map(item => <button key={item} className={category === item ? "active" : ""} onClick={() => setCategory(item)}>{item}</button>)}</div>
    </section>

    <div className="directory-results-heading"><div><SlidersHorizontal size={14}/><strong>{filtered.length} servers</strong><span>matching the current view</span></div><p>Popularity reflects public assessment activity, not server usage.</p></div>

    {loading ? <DirectoryLoading/> : filtered.length === 0 ? <section className="card directory-empty"><BookOpen size={24}/><strong>No servers match these filters.</strong><p>Clear a filter or run an assessment to add fresh public evidence.</p><button className="button" onClick={() => { setQuery(""); setCategory("All"); setAuthentication("All"); setRisk("All"); setDeployment("All"); setOfficialOnly(false); }}>Clear filters</button></section> : <section className="directory-grid" aria-label="MCP servers">{filtered.map(entry => <ServerCard key={entry.key} entry={entry}/>)}</section>}

    <div className="directory-boundary"><ShieldCheck size={14}/><span><strong>Assessment boundary:</strong> directory data comes from metadata and declared contracts. No MCP tools are executed, no prompts are sent, and no payload fuzzing occurs.</span></div>
  </div>;
}

function ServerCard({ entry }: { entry: DirectoryEntry }) {
  const score = entry.assessment.scorecard.overall;
  return <Link className="directory-server-card" href={`/reports/${entry.summary.id}`} aria-label={`Open the latest public report for ${entry.name}`}>
    <div className={`directory-readiness-line ${readinessTone(score)}`} style={{ "--readiness": `${score}%` } as React.CSSProperties}/>
    <div className="directory-card-header">
      <span className="directory-server-mark">{serverInitials(entry.name)}</span>
      <div><h2>{entry.name}</h2><p>{entry.host}</p></div>
      <div className="directory-card-badges">{entry.official && <span className="directory-badge official" title="Publisher endpoint verified"><BadgeCheck size={12}/>Official</span>}<span className={`directory-badge ${entry.deployment.toLowerCase()}`}>{entry.deployment === "Remote" ? <Globe2 size={12}/> : <Laptop size={12}/>} {entry.deployment}</span></div>
    </div>
    <div className="directory-category"><Building2 size={12}/>{entry.category}</div>
    <p className="directory-summary">{serverSummary(entry)}</p>
    <dl className="directory-posture">
      <div><dt><CircleGauge size={13}/>Readiness</dt><dd><strong>{score}</strong><span>/100</span></dd></div>
      <div><dt><ShieldCheck size={13}/>Risk</dt><dd><span className={`directory-risk ${entry.risk.toLowerCase()}`}>{entry.risk}</span></dd></div>
      <div><dt><KeyRound size={13}/>Authentication</dt><dd>{entry.authentication}</dd></div>
    </dl>
    <div className="directory-card-footer">
      <div><span>Latest assessment</span><strong>{format(new Date(entry.summary.createdAt), "MMM d, yyyy")}</strong></div>
      <div><span>Popularity</span><strong><Users size={12}/>{entry.assessmentCount} public {entry.assessmentCount === 1 ? "report" : "reports"}</strong></div>
      <span className="directory-open-report">View public report <ArrowRight size={13}/></span>
    </div>
  </Link>;
}

function DirectoryLoading() {
  return <section className="directory-grid" aria-label="Loading MCP servers" role="status" aria-live="polite" aria-busy="true"><span className="sr-only">Loading assessed MCP servers</span>{[1, 2, 3, 4, 5, 6].map(item => <div className="card directory-card-skeleton" aria-hidden="true" key={item}><span className="skeleton"/><div className="skeleton"/><div className="skeleton"/></div>)}</section>;
}

function latestPublicAssessments(items: AssessmentSummary[]) {
  const groups = new Map<string, AssessmentSummary[]>();
  items.filter(item => item.mode === "live" && ["completed", "partial"].includes(item.status) && !["authentication-required", "connection-failed"].includes(item.connectionStatus)).forEach(item => {
    const key = canonicalTarget(item.target.url);
    groups.set(key, [...(groups.get(key) || []), item]);
  });
  return [...groups.entries()].map(([key, assessments]) => {
    const sorted = assessments.sort((left, right) => Date.parse(right.createdAt) - Date.parse(left.createdAt));
    return { key, latest: sorted[0], count: assessments.length };
  });
}

function toDirectoryEntry(key: string, summary: AssessmentSummary, assessmentCount: number, assessment: Assessment): DirectoryEntry {
  const host = summary.target.host || safeHost(summary.target.url);
  const publisher = verifiedPublishers[host];
  return {
    key,
    name: publisher?.name || assessment.server.name || humanizeHost(host),
    host,
    assessment,
    summary,
    assessmentCount,
    category: publisher?.category || serverCategory(assessment),
    authentication: authenticationType(assessment),
    risk: riskLevel(assessment),
    official: Boolean(publisher),
    deployment: deploymentType(summary.target.url),
  };
}

function serverCategory(assessment: Assessment) {
  const counts = new Map<string, number>();
  assessment.tools.forEach(tool => {
    const category = normalizeCategory(tool.classification.domain || tool.classification.operationType || tool.categories[0] || "General");
    counts.set(category, (counts.get(category) || 0) + 1);
  });
  return [...counts.entries()].sort((left, right) => right[1] - left[1])[0]?.[0] || "General";
}

function normalizeCategory(value: string) {
  const normalized = value.toLowerCase().replaceAll("_", " ").replaceAll("-", " ");
  if (/develop|code|repository|source control/.test(normalized)) return "Developer Tools";
  if (/project|product|productivity|task|planning/.test(normalized)) return "Productivity";
  if (/database|data|analytics|search/.test(normalized)) return "Data & Databases";
  if (/cloud|infrastructure|devops|deploy/.test(normalized)) return "Cloud & Infrastructure";
  if (/communication|collaboration|message|email/.test(normalized)) return "Communication";
  if (/finance|payment|commerce|billing/.test(normalized)) return "Finance & Commerce";
  if (/file|storage|document/.test(normalized)) return "Files & Storage";
  return normalized === "unknown" || !normalized ? "General" : normalized.replace(/\b\w/g, character => character.toUpperCase());
}

function authenticationType(assessment: Assessment): AuthenticationType {
  const authentication = assessment.server.authentication?.toLowerCase() || "";
  if (assessment.oauth.authorizationCompleted || assessment.oauth.authorizationServerMetadataValid || authentication.includes("oauth")) return "OAuth";
  if (authentication.includes("bearer") || authentication.includes("token")) return "Bearer Token";
  if (authentication.includes("header") || authentication.includes("api-key") || authentication.includes("api key")) return "Custom Headers";
  if (!assessment.oauth.protected && ["none", "anonymous", "optional"].some(value => authentication.includes(value))) return "Anonymous";
  return "Not Assessed";
}

function riskLevel(assessment: Assessment): RiskLevel {
  if (assessment.risk.critical > 0) return "Critical";
  if (assessment.risk.high > 0) return "High";
  if (assessment.risk.medium > 0) return "Moderate";
  return "Low";
}

function serverSummary(entry: DirectoryEntry) {
  if (entry.assessment.executiveSummary) return entry.assessment.executiveSummary;
  const toolCount = entry.assessment.server.toolCount || entry.assessment.tools.length;
  return `${toolCount} advertised ${toolCount === 1 ? "tool" : "tools"} assessed for contract quality, identity exposure, authentication, and operational readiness.`;
}

function canonicalTarget(value: string) { return value.toLowerCase().replace(/\/$/, ""); }
function safeHost(value: string) { try { return new URL(value).hostname; } catch { return value; } }
function deploymentType(value: string): "Remote" | "Local" { const host = safeHost(value).toLowerCase(); return host === "localhost" || host === "127.0.0.1" || host === "host.docker.internal" || host.endsWith(".local") ? "Local" : "Remote"; }
function humanizeHost(host: string) { return host.replace(/^mcp\./, "").replace(/^api\./, "").split(".")[0].replace(/[-_]/g, " ").replace(/\b\w/g, character => character.toUpperCase()); }
function serverInitials(name: string) { return name.split(/\s+/).slice(0, 2).map(part => part[0]).join("").toUpperCase(); }
function riskRank(value: RiskLevel) { return ({ Low: 0, Moderate: 1, High: 2, Critical: 3 } as Record<RiskLevel, number>)[value]; }
function readinessTone(score: number) { return score >= 80 ? "strong" : score >= 60 ? "developing" : "needs"; }
