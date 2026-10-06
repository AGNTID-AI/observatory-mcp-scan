"use client";

import { useEffect, useState } from "react";
import { AlertTriangle, Check, CircleX, LoaderCircle, LockKeyhole, Network, ShieldCheck, SlidersHorizontal } from "lucide-react";
import { api } from "@/lib/api";
import { Card, PageHeading } from "@/components/page";

interface EffectiveSettings { interactiveOAuth:boolean; dynamicClientRegistration:boolean; oauthPKCE:string; limits:{concurrentAssessments:number;assessmentTimeoutSeconds:number;stageTimeoutSeconds:number;maxItems:number}; networkPolicy:{publicTargets:boolean;privateTargets:boolean;loopbackTargets:boolean} }

export default function Settings() {
  const [settings, setSettings] = useState<EffectiveSettings | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api.settings()
      .then(value => setSettings(value as unknown as EffectiveSettings))
      .catch(cause => setError(cause instanceof Error ? cause.message : "Unable to load settings."));
  }, []);

  return <>
    <PageHeading eyebrow="Workspace" title="Settings" description="Review the limits and safety rules Observatory currently uses." actions={<span className="badge neutral"><LockKeyhole size={12}/>Read only</span>}/>
    <div className="notice settings-readonly"><LockKeyhole size={17}/><div><strong>These settings are view-only</strong><p>They are managed by the Observatory deployment and cannot be changed from this screen.</p></div></div>
    {error ? <div className="state-panel card danger" role="alert"><AlertTriangle size={22}/><div><strong>Settings could not be loaded</strong><span>{error}</span></div></div> : !settings ? <div className="state-panel card" role="status" aria-live="polite" aria-busy="true"><LoaderCircle className="animate-spin" size={22}/><div><strong>Loading current settings</strong><span>Retrieving deployment limits and safety controls.</span></div></div> : <div className="grid two-column settings-layout">
      <Card title="Assessment limits" description="How much work Observatory can perform during an assessment.">
        <Setting icon={<SlidersHorizontal size={14}/>} label="Assessments running at the same time" value={String(settings.limits.concurrentAssessments)}/>
        <Setting icon={<SlidersHorizontal size={14}/>} label="Maximum time for one assessment" value={`${settings.limits.assessmentTimeoutSeconds} seconds`}/>
        <Setting icon={<SlidersHorizontal size={14}/>} label="Maximum time for one assessment step" value={`${settings.limits.stageTimeoutSeconds} seconds`}/>
        <Setting icon={<SlidersHorizontal size={14}/>} label="Maximum catalog items inspected" value={String(settings.limits.maxItems)}/>
      </Card>
      <div className="grid">
        <Card title="Targets Observatory can assess" description="Which network locations an assessment is allowed to contact.">
          <Setting icon={<Network size={14}/>} label="Public internet addresses" value={settings.networkPolicy.publicTargets ? "Can assess" : "Blocked"} blocked={!settings.networkPolicy.publicTargets}/>
          <Setting icon={<Network size={14}/>} label="Private network addresses" value={settings.networkPolicy.privateTargets ? "Can assess" : "Blocked"} blocked={!settings.networkPolicy.privateTargets}/>
          <Setting icon={<LockKeyhole size={14}/>} label="This computer (loopback)" value={settings.networkPolicy.loopbackTargets ? "Can assess" : "Blocked"} blocked={!settings.networkPolicy.loopbackTargets}/>
          <Setting icon={<LockKeyhole size={14}/>} label="Link-local and cloud metadata addresses" value="Blocked" blocked/>
        </Card>
        <Card title="Built-in safety protections" description="Controls that limit what Observatory does during an assessment.">
          <div className="notice settings-safety"><ShieldCheck size={16}/><div><strong>MCP tools are never called</strong><p>Observatory reads advertised metadata only. It does not execute discovered tools or send fuzzing payloads.</p></div></div>
          <div className="settings-protections"><Protection label="Credentials are encrypted"/><Protection label="Tool execution is disabled"/>{settings.interactiveOAuth && <Protection label="Browser OAuth is available"/>}{settings.dynamicClientRegistration && <Protection label="OAuth client registration is supported"/>}{settings.oauthPKCE && <Protection label={`OAuth uses PKCE ${settings.oauthPKCE}`}/>}</div>
        </Card>
      </div>
    </div>}
  </>;
}

function Setting({ icon, label, value, blocked = false }: { icon: React.ReactNode; label: string; value: string; blocked?: boolean }) {
  return <div className="setting-row"><span>{icon}</span><span>{label}</span><strong className={blocked ? "blocked" : "allowed"}>{blocked ? <CircleX size={12}/> : <Check size={12}/>} {value}</strong></div>;
}

function Protection({ label }: { label: string }) { return <span><Check size={12}/>{label}</span>; }
