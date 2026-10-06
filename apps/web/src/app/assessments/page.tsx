"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import {
  ArrowRight,
  BarChart3,
  FileSearch,
  GitCompareArrows,
  Globe2,
  KeyRound,
  LibraryBig,
  Minus,
  Plus,
  Search,
  ShieldAlert,
  TrendingDown,
  TrendingUp,
} from "lucide-react";
import { format } from "date-fns";
import { api } from "@/lib/api";
import type { Assessment, AssessmentSummary } from "@/lib/types";
import { assessmentDisplayStatus, AssessmentStatusBadge, PageHeading } from "@/components/page";

type AssessmentGroup = { key: string; label: string; items: AssessmentSummary[] };
type Comparison = { baseline: Assessment; current: Assessment };

export default function AssessmentHistory() {
  const [items, setItems] = useState<AssessmentSummary[]>([]);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const [source, setSource] = useState("all");
  const [loading, setLoading] = useState(true);
  const [selectedTarget, setSelectedTarget] = useState("");
  const [baselineId, setBaselineId] = useState("");
  const [currentId, setCurrentId] = useState("");
  const [comparison, setComparison] = useState<Comparison | null>(null);
  const [comparisonLoading, setComparisonLoading] = useState(false);
  const [comparisonError, setComparisonError] = useState("");

  useEffect(() => {
    const requested = new URLSearchParams(window.location.search).get("source");
    if (["live", "offline", "sample"].includes(requested || "")) setSource(requested || "all");
    api.assessments().then(response => setItems(response.items)).finally(() => setLoading(false));
  }, []);

  const comparableGroups = useMemo(() => groupAssessments(items), [items]);
  const selectedGroup = comparableGroups.find(group => group.key === selectedTarget);

  useEffect(() => {
    if (!selectedTarget && comparableGroups.length) setSelectedTarget(comparableGroups[0].key);
  }, [comparableGroups, selectedTarget]);

  useEffect(() => {
    if (!selectedGroup) return;
    setCurrentId(selectedGroup.items[0]?.id || "");
    setBaselineId(selectedGroup.items[1]?.id || "");
  }, [selectedGroup]);

  useEffect(() => {
    if (!baselineId || !currentId || baselineId === currentId) {
      setComparison(null);
      return;
    }
    let active = true;
    setComparisonLoading(true);
    setComparisonError("");
    Promise.all([api.assessment(baselineId), api.assessment(currentId)])
      .then(([baseline, current]) => { if (active) setComparison({ baseline, current }); })
      .catch(error => { if (active) setComparisonError(error instanceof Error ? error.message : "Unable to compare these reports."); })
      .finally(() => { if (active) setComparisonLoading(false); });
    return () => { active = false; };
  }, [baselineId, currentId]);

  const filtered = useMemo(() => items.filter(item =>
    (source === "all" || item.mode === source) &&
    (status === "all" || assessmentDisplayStatus(item.status, item.connectionStatus) === status) &&
    `${item.target.url} ${item.target.host || ""}`.toLowerCase().includes(query.toLowerCase())
  ), [items, query, status, source]);

  const prepareComparison = (item: AssessmentSummary) => {
    const group = comparableGroups.find(candidate => candidate.key === targetKey(item));
    if (!group || group.items.length < 2) return;
    const index = group.items.findIndex(candidate => candidate.id === item.id);
    const baseline = group.items[index + 1] || group.items[index - 1];
    setSelectedTarget(group.key);
    setCurrentId(item.id);
    setBaselineId(baseline.id);
    window.requestAnimationFrame(() => document.getElementById("assessment-comparison")?.scrollIntoView({ behavior: "smooth", block: "start" }));
  };

  return <div className="assessment-history-page">
    <PageHeading
      eyebrow="Assessment workspace"
      title="Assessment History"
      description="Track readiness, risk, authentication, and catalog changes across repeat assessments."
      actions={<Link href="/assessments/new" className="button primary"><Plus size={14}/>Start new assessment</Link>}
    />

    <section className="card history-comparison-card" id="assessment-comparison" aria-labelledby="comparison-title">
      <div className="history-section-heading">
        <div className="history-heading-copy"><span><GitCompareArrows size={17}/></span><div><div className="section-label">Compare over time</div><h2 id="comparison-title">Readiness trend</h2><p>Select two reports for the same endpoint to understand what changed.</p></div></div>
        {comparableGroups.length > 0 && <label className="history-target-select"><span>Target MCP endpoint</span><select className="select" value={selectedTarget} onChange={event => setSelectedTarget(event.target.value)}>{comparableGroups.map(group => <option key={group.key} value={group.key}>{group.label} · {group.items.length} reports</option>)}</select></label>}
      </div>

      {loading ? <div className="history-comparison-empty" role="status" aria-live="polite" aria-busy="true">Loading assessment history…</div> : comparableGroups.length === 0 ? <div className="history-comparison-empty"><BarChart3 size={22}/><div><strong>A trend begins with a second assessment.</strong><p>Reassess the same MCP endpoint to compare readiness and control changes over time.</p></div><Link href="/assessments/new" className="button">Start another assessment</Link></div> : selectedGroup && <>
        <div className="history-compare-selectors">
          <ReportSelector label="Baseline report" value={baselineId} items={selectedGroup.items.filter(item => item.id !== currentId)} onChange={setBaselineId}/>
          <ArrowRight size={17}/>
          <ReportSelector label="Comparison report" value={currentId} items={selectedGroup.items.filter(item => item.id !== baselineId)} onChange={setCurrentId}/>
          <div className="history-report-actions"><Link className="button" href={`/reports/${baselineId}`}>Open baseline</Link><Link className="button" href={`/reports/${currentId}`}>Open comparison</Link></div>
        </div>

        <div className="history-trend-layout">
          <TrendChart items={selectedGroup.items}/>
          <div className="history-change-summary">
            {comparisonLoading ? <div className="history-comparison-loading">Comparing report evidence…</div> : comparisonError ? <div className="history-comparison-error">{comparisonError}</div> : comparison && <ComparisonChanges comparison={comparison}/>}
          </div>
        </div>
        <p className="history-comparison-note">Changes reflect observed metadata and the evidence available in each assessment. Catalog visibility does not prove permission to execute a tool.</p>
      </>}
    </section>

    <section className="card history-list-card" aria-labelledby="all-assessments-title">
      <div className="history-list-heading"><div><div className="section-label">Assessment record</div><h2 id="all-assessments-title">All assessments</h2></div><span>{filtered.length} shown</span></div>
      <div className="history-filters toolbar">
        <div className="history-search"><Search size={14}/><input className="input" placeholder="Search target endpoint…" value={query} onChange={event => setQuery(event.target.value)}/></div>
        <select className="select" aria-label="Filter by source" value={source} onChange={event => setSource(event.target.value)}><option value="all">All assessment sources</option><option value="live">Live metadata</option><option value="offline">Uploaded metadata</option><option value="sample">Guided examples</option></select>
        <select className="select" aria-label="Filter by status" value={status} onChange={event => setStatus(event.target.value)}><option value="all">All statuses</option><option value="completed">Completed</option><option value="partial">Partial checks</option><option value="authentication-required">Authentication required</option><option value="connection-failed">Connection failed</option><option value="running">Running</option><option value="failed">Failed</option></select>
      </div>
      {loading ? <div className="empty" role="status" aria-live="polite" aria-busy="true">Loading assessments…</div> : filtered.length === 0 && source === "live" ? <div className="empty"><Globe2 size={28}/><strong>No live metadata assessments are available yet.</strong><span>Assess a publicly reachable MCP server to add its history here.</span><Link className="button" href="/assessments/new">Start an assessment</Link></div> : filtered.length === 0 ? <div className="empty"><FileSearch size={28}/>No assessments match these filters.</div> : <AssessmentTable items={filtered} groups={comparableGroups} onCompare={prepareComparison}/>}
    </section>
  </div>;
}

function ReportSelector({ label, value, items, onChange }: { label: string; value: string; items: AssessmentSummary[]; onChange: (value: string) => void }) {
  return <label><span>{label}</span><select className="select" value={value} onChange={event => onChange(event.target.value)}>{items.map(item => <option key={item.id} value={item.id}>{format(new Date(item.createdAt), "MMM d, yyyy · HH:mm")} · {item.overallScore}/100</option>)}</select></label>;
}

function TrendChart({ items }: { items: AssessmentSummary[] }) {
  const chronological = [...items].sort((left, right) => Date.parse(left.createdAt) - Date.parse(right.createdAt));
  const width = 620;
  const height = 130;
  const inset = 18;
  const points = chronological.map((item, index) => ({
    x: chronological.length === 1 ? width / 2 : inset + index * ((width - inset * 2) / (chronological.length - 1)),
    y: height - inset - (Math.max(0, Math.min(100, item.overallScore)) / 100) * (height - inset * 2),
    item,
  }));
  const change = chronological.at(-1)!.overallScore - chronological[0].overallScore;
  return <div className="readiness-trend">
    <div className="trend-heading"><div><span>Readiness over time</span><strong>{chronological.length} comparable reports</strong></div><TrendValue value={change} suffix=" points"/></div>
    <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`Readiness changed by ${change} points across ${chronological.length} reports`}>
      <line x1={inset} y1={height - inset} x2={width - inset} y2={height - inset}/>
      <line x1={inset} y1={height / 2} x2={width - inset} y2={height / 2}/>
      <polyline points={points.map(point => `${point.x},${point.y}`).join(" ")}/>
      {points.map(point => <g key={point.item.id}><circle cx={point.x} cy={point.y} r="5"/><text x={point.x} y={point.y - 11}>{point.item.overallScore}</text></g>)}
    </svg>
    <div className="trend-axis"><span>{format(new Date(chronological[0].createdAt), "MMM d, yyyy")}</span><span>{format(new Date(chronological.at(-1)!.createdAt), "MMM d, yyyy")}</span></div>
  </div>;
}

function ComparisonChanges({ comparison }: { comparison: Comparison }) {
  const { baseline, current } = comparison;
  const readinessChange = current.scorecard.overall - baseline.scorecard.overall;
  const baselineRisks = priorityRiskCount(baseline);
  const currentRisks = priorityRiskCount(current);
  const riskChange = currentRisks - baselineRisks;
  const baselineAuth = authenticationState(baseline);
  const currentAuth = authenticationState(current);
  const catalog = catalogChanges(baseline, current);
  return <>
    <ChangeCard icon={<TrendingUp size={16}/>} title={readinessChange > 0 ? "Readiness improvement" : "Readiness change"} value={<TrendValue value={readinessChange} suffix=" points"/>} detail={`${baseline.scorecard.overall}/100 → ${current.scorecard.overall}/100`}/>
    <ChangeCard icon={<ShieldAlert size={16}/>} title="Priority risk changes" value={<RiskTrend value={riskChange}/>} detail={`${baselineRisks} → ${currentRisks} critical or high`}/>
    <ChangeCard icon={<KeyRound size={16}/>} title="Authentication changes" value={baselineAuth === currentAuth ? "No material change" : "Changed"} detail={baselineAuth === currentAuth ? currentAuth : `${baselineAuth} → ${currentAuth}`}/>
    <ChangeCard icon={<LibraryBig size={16}/>} title="Catalog changes" value={catalog.total === 0 ? "No catalog change" : `${catalog.total} ${catalog.total === 1 ? "change" : "changes"}`} detail={`${catalog.added} added · ${catalog.removed} removed · ${catalog.modified} modified`}/>
  </>;
}

function ChangeCard({ icon, title, value, detail }: { icon: React.ReactNode; title: string; value: React.ReactNode; detail: string }) {
  return <article className="history-change-card"><span>{icon}</span><div><small>{title}</small><strong>{value}</strong><p>{detail}</p></div></article>;
}

function AssessmentTable({ items, groups, onCompare }: { items: AssessmentSummary[]; groups: AssessmentGroup[]; onCompare: (item: AssessmentSummary) => void }) {
  return <div className="table-wrap"><table className="history-table"><thead><tr><th>Target</th><th>Status</th><th>Readiness</th><th>Trend</th><th>Priority risk</th><th>Assessed</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{items.map(item => {
    const assessed = isComparable(item);
    const group = groups.find(candidate => candidate.key === targetKey(item));
    const trend = assessed && group ? comparisonTrend(item, group.items) : null;
    return <tr key={item.id}>
      <td><Link className="target-cell" href={`/assessments/${item.id}`}><strong>{item.target.host || item.target.url}</strong><span>{AssessmentSourceLabel(item.mode)} · {item.target.url}</span></Link></td>
      <td><AssessmentStatusBadge status={item.status} connectionStatus={item.connectionStatus}/></td>
      <td>{assessed ? <div className="score-inline"><b>{item.overallScore}</b><div className="mini-progress"><span style={{ width: `${item.overallScore}%` }}/></div></div> : <span className="muted">Not assessed</span>}</td>
      <td>{trend === null ? <span className="history-no-trend"><Minus size={12}/>Baseline</span> : <TrendValue value={trend}/>}</td>
      <td>{assessed ? <span className={priorityRiskCount(item) > 0 ? "priority-risk-count active" : "priority-risk-count"}>{priorityRiskCount(item)} critical/high</span> : "—"}</td>
      <td className="history-date">{format(new Date(item.createdAt), "MMM d, yyyy")}<small>{format(new Date(item.createdAt), "HH:mm")}</small></td>
      <td><div className="history-row-actions">{group && group.items.length > 1 && assessed && <button className="button" onClick={() => onCompare(item)}><GitCompareArrows size={13}/>Compare</button>}<Link className="button icon-button" title="Open report" aria-label={`Open report for ${item.target.host || item.target.url}`} href={`/reports/${item.id}`}><ArrowRight size={14}/></Link></div></td>
    </tr>;
  })}</tbody></table></div>;
}

function TrendValue({ value, suffix = "" }: { value: number; suffix?: string }) {
  if (value === 0) return <span className="trend-value neutral"><Minus size={12}/>No change</span>;
  const Icon = value > 0 ? TrendingUp : TrendingDown;
  return <span className={`trend-value ${value > 0 ? "positive" : "negative"}`}><Icon size={13}/>{value > 0 ? "+" : ""}{value}{suffix}</span>;
}

function RiskTrend({ value }: { value: number }) {
  if (value === 0) return <span className="trend-value neutral"><Minus size={12}/>No change</span>;
  const improved = value < 0;
  const Icon = improved ? TrendingDown : TrendingUp;
  return <span className={`trend-value ${improved ? "positive" : "negative"}`}><Icon size={13}/>{Math.abs(value)} {improved ? "fewer" : "more"}</span>;
}

function groupAssessments(items: AssessmentSummary[]): AssessmentGroup[] {
  const grouped = new Map<string, AssessmentSummary[]>();
  items.filter(isComparable).forEach(item => {
    const key = targetKey(item);
    grouped.set(key, [...(grouped.get(key) || []), item]);
  });
  return [...grouped.entries()].map(([key, group]) => ({
    key,
    label: group[0].target.host || group[0].target.url,
    items: group.sort((left, right) => Date.parse(right.createdAt) - Date.parse(left.createdAt)),
  })).filter(group => group.items.length >= 2).sort((left, right) => right.items.length - left.items.length);
}

function comparisonTrend(item: AssessmentSummary, group: AssessmentSummary[]) {
  const index = group.findIndex(candidate => candidate.id === item.id);
  const previous = group[index + 1];
  return previous ? item.overallScore - previous.overallScore : null;
}

function catalogChanges(baseline: Assessment, current: Assessment) {
  const before = new Map(baseline.tools.map(tool => [tool.name, tool.fingerprint]));
  const after = new Map(current.tools.map(tool => [tool.name, tool.fingerprint]));
  const added = [...after.keys()].filter(name => !before.has(name)).length;
  const removed = [...before.keys()].filter(name => !after.has(name)).length;
  const modified = [...after.entries()].filter(([name, fingerprint]) => before.has(name) && before.get(name) !== fingerprint).length;
  return { added, removed, modified, total: added + removed + modified };
}

function authenticationState(assessment: Assessment) {
  if (!assessment.oauth.protected && assessment.server.authentication === "none") return "Anonymous access observed";
  if (assessment.oauth.authorizationCompleted) return "OAuth authorized";
  if (assessment.oauth.resourceMetadataValid && assessment.oauth.authorizationServerMetadataValid) return "OAuth metadata validated";
  if (assessment.oauth.protected || assessment.server.authentication === "required") return "Protected; metadata incomplete";
  if (assessment.server.authentication?.toLowerCase() === "oauth") return "OAuth";
  return assessment.server.authentication && assessment.server.authentication !== "not-assessed" ? titleCase(assessment.server.authentication) : "Not fully assessed";
}

function priorityRiskCount(assessment: Pick<AssessmentSummary, "risk">) { return assessment.risk.critical + assessment.risk.high; }
function isComparable(item: AssessmentSummary) { return ["completed", "partial"].includes(item.status) && !["authentication-required", "connection-failed"].includes(item.connectionStatus); }
function targetKey(item: AssessmentSummary) { return item.target.url.toLowerCase().replace(/\/$/, ""); }
function AssessmentSourceLabel(mode: string) { return ({ live: "Live metadata", offline: "Uploaded metadata", sample: "Guided example" } as Record<string, string>)[mode] || titleCase(mode); }
function titleCase(value: string) { return value.replaceAll("-", " ").replace(/\b\w/g, character => character.toUpperCase()); }
