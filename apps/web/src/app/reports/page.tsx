"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { AlertTriangle, ArrowRight, FileText, LoaderCircle, Plus } from "lucide-react";
import { api } from "@/lib/api";
import type { AssessmentSummary } from "@/lib/types";
import { AssessmentStatusBadge, PageHeading, StatusBadge } from "@/components/page";

export default function Reports() {
  const [items, setItems] = useState<AssessmentSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    api.assessments()
      .then(response => setItems(response.items.filter(item => ["completed", "partial"].includes(item.status))))
      .catch(cause => setError(cause instanceof Error ? cause.message : "Unable to load reports."))
      .finally(() => setLoading(false));
  }, []);

  return <>
    <PageHeading eyebrow="Reporting" title="Report Viewer" description="Executive summaries and technical evidence, ready to review or share."/>
    <section className="card report-library" aria-label="Assessment reports">
      {loading ? <div className="state-panel" role="status" aria-live="polite" aria-busy="true"><LoaderCircle className="animate-spin" size={22}/><div><strong>Loading assessment reports</strong><span>Retrieving the latest completed and partial assessments.</span></div></div> : error ? <div className="state-panel danger" role="alert"><AlertTriangle size={22}/><div><strong>Reports could not be loaded</strong><span>{error}</span></div></div> : items.length === 0 ? <div className="empty"><FileText size={28}/><strong>No reports yet</strong><span>Completed readiness assessments will appear here.</span><Link className="button primary" href="/assessments/new"><Plus size={13}/>Start an assessment</Link></div> : <div className="table-wrap"><table><caption className="sr-only">Available MCP readiness reports</caption><thead><tr><th>Target</th><th>Status</th><th>Readiness</th><th>Coverage</th><th><span className="sr-only">Open report</span></th></tr></thead><tbody>{items.map(item => {
        const assessed = !["authentication-required", "connection-failed"].includes(item.connectionStatus);
        return <tr key={item.id}>
          <td><Link className="report-target" title={item.target.url} href={`/reports/${item.id}`}><FileText size={15}/><div><strong>{item.target.host || item.target.url}</strong><StatusBadge value={item.mode}/></div></Link></td>
          <td><AssessmentStatusBadge status={item.status} connectionStatus={item.connectionStatus}/></td>
          <td>{assessed ? <div className="score-inline"><b>{item.overallScore}</b><div className="mini-progress"><span style={{ width: `${item.overallScore}%` }}/></div></div> : <span className="muted">Not assessed</span>}</td>
          <td>{assessed ? <div className="coverage-inline"><span style={{ width: `${item.coverage}%` }}/>{Math.round(item.coverage)}%</div> : "—"}</td>
          <td className="table-action"><Link className="button icon-button" title="Open report" aria-label={`Open report for ${item.target.host || item.target.url}`} href={`/reports/${item.id}`}><ArrowRight size={15}/></Link></td>
        </tr>;
      })}</tbody></table></div>}
    </section>
  </>;
}
