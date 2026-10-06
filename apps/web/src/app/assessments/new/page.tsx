"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { ArrowRight, Braces, Check, ExternalLink, FileCheck2, FileJson2, Fingerprint, Globe2, KeyRound, Library, LoaderCircle, LockKeyhole, Network, Plus, RefreshCw, ShieldCheck, Trash2, Upload, UserRoundCheck, Users, X } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import type { OAuthSession, OfflineSnapshot } from "@/lib/types";
import { PageHeading, StatusBadge } from "@/components/page";

type Header={name:string;value:string};
type CredentialProfile={id:number;label:string;token:string;headers:Header[];oauth?:OAuthSession;connecting?:boolean};
const newProfile=(id:number,label="Reader")=>({id,label,token:"",headers:[]} as CredentialProfile);

export default function NewAssessment(){
  const router=useRouter();
  const nextProfileID=useRef(2);
  const [mode,setMode]=useState<"live"|"offline">("live");
  const [url,setUrl]=useState("");
  const [snapshot,setSnapshot]=useState<OfflineSnapshot|null>(null);
  const [profiles,setProfiles]=useState<CredentialProfile[]>([newProfile(1)]);
  const [submitting,setSubmitting]=useState(false);
  const [rerunNeedsSignIn,setRerunNeedsSignIn]=useState(false);
  useEffect(()=>{const query=new URLSearchParams(window.location.search);const requestedMode=query.get("mode");const target=query.get("target");if(requestedMode==="offline")setMode("offline");if(target)setUrl(target);setRerunNeedsSignIn(query.get("signin")==="required")},[]);
  const update=(id:number,fn:(p:CredentialProfile)=>CredentialProfile)=>setProfiles(items=>items.map(p=>p.id===id?fn(p):p));

  const connectOAuth=async(profile:CredentialProfile)=>{
    if(!url) return toast.error("Enter the MCP server URL first.");
    if(!profile.label.trim()) return toast.error("Name this identity before connecting OAuth.");
    const popup=window.open("about:blank",`observatory-oauth-${profile.id}`,"popup,width=620,height=760");
    update(profile.id,p=>({...p,connecting:true,oauth:undefined}));
    try{
      let session=await api.startOAuth(url,profile.label.trim());
      update(profile.id,p=>({...p,connecting:false,oauth:session}));
      if(session.status==="not-required"){
        popup?.close();toast.info("This endpoint accepted anonymous initialization; OAuth was not required.");return;
      }
      if(!session.authorizationUrl){
        popup?.close();throw new Error(session.error||"This server did not provide a usable DCR authorization path.");
      }
      if(popup) popup.location.href=session.authorizationUrl;
      else window.open(session.authorizationUrl,"_blank","noopener,noreferrer");
      const expiresAt=new Date(session.expiresAt).getTime();
      while(Date.now()<expiresAt){
        await new Promise(resolve=>setTimeout(resolve,1200));
        session=await api.oauthSession(session.id);
        update(profile.id,p=>({...p,oauth:session,connecting:false,...(session.status==="authorized"?{token:"",headers:[]}: {})}));
        if(session.status==="authorized"){
          popup?.close();toast.success(`${profile.label} connected with OAuth and DCR`);return;
        }
        if(["failed","denied","expired","canceled","unsupported"].includes(session.status)){
          popup?.close();throw new Error(session.error||`OAuth authorization ${session.status}.`);
        }
      }
      throw new Error("OAuth authorization expired.");
    }catch(error){
      popup?.close();update(profile.id,p=>({...p,connecting:false}));toast.error(error instanceof Error?error.message:"OAuth connection failed");
    }
  };

  const disconnectOAuth=async(profile:CredentialProfile)=>{
    if(profile.oauth) await api.cancelOAuth(profile.oauth.id).catch(()=>undefined);
    update(profile.id,p=>({...p,oauth:undefined,connecting:false}));
  };
  const submit=async(e:React.FormEvent)=>{
    e.preventDefault();setSubmitting(true);
    try{
      const credentialProfiles=mode==="live"?profiles.filter(p=>p.label&&(p.oauth?.status==="authorized"||p.token||p.headers.some(h=>h.name&&h.value))).map(p=>({label:p.label,bearerToken:p.oauth?.status==="authorized"?undefined:p.token||undefined,headers:p.oauth?.status==="authorized"?undefined:Object.fromEntries(p.headers.filter(h=>h.name&&h.value).map(h=>[h.name,h.value])),oauthSessionId:p.oauth?.status==="authorized"?p.oauth.id:undefined})):undefined;
      if(mode==="offline"&&!snapshot) throw new Error("Choose a saved server data JSON file first.");
      const targetURL=mode==="offline"?(url||snapshot?.targetUrl||""):url;
      const result=await api.create({mode,target:{protocol:"mcp",url:targetURL},credentialProfiles,snapshot:mode==="offline"?snapshot??undefined:undefined});
      toast.success("Assessment queued");router.push(`/assessments/${result.assessmentId}`);
    }catch(error){toast.error(error instanceof Error?error.message:"Unable to queue assessment");setSubmitting(false)}
  };
  const loadSnapshot=async(file:File)=>{
    try{
      const raw=JSON.parse(await file.text()) as Record<string,unknown>;
      const candidate=(raw.snapshot&&typeof raw.snapshot==="object"?raw.snapshot:raw) as Record<string,unknown>;
      const nestedServer=(candidate.server&&typeof candidate.server==="object"?candidate.server:{}) as Record<string,unknown>;
      const tools=(Array.isArray(candidate.tools)?candidate.tools:Array.isArray(nestedServer.tools)?nestedServer.tools:[]) as OfflineSnapshot["tools"];
      if(tools.length===0) throw new Error("No MCP tool list was found in this file.");
      const parsed={name:String(candidate.name||file.name.replace(/\.json$/i,"")),targetUrl:typeof candidate.targetUrl==="string"?candidate.targetUrl:undefined,serverInstructions:typeof candidate.serverInstructions==="string"?candidate.serverInstructions:undefined,server:nestedServer,tools,prompts:Array.isArray(candidate.prompts)?candidate.prompts as OfflineSnapshot["prompts"]:[],resources:Array.isArray(candidate.resources)?candidate.resources as OfflineSnapshot["resources"]:[]} satisfies OfflineSnapshot;
      setSnapshot(parsed);setUrl(parsed.targetUrl||"");toast.success(`Loaded ${tools.length} tool declarations`);
    }catch(error){setSnapshot(null);toast.error(error instanceof Error?error.message:"This file could not be read as saved MCP server data.")}
  };
  return <div className="new-assessment-page">
    <PageHeading eyebrow="Free readiness assessment" title="Prepare your MCP readiness assessment" description="Provide the endpoint and access perspectives you want represented. Observatory will turn the declared MCP surface into a clear, evidence-based report."/>
    {rerunNeedsSignIn&&<div className="notice rerun-notice"><KeyRound size={16}/><span><strong>Reconnect this identity for the new assessment.</strong><br/>Access details are never copied from an earlier report.</span></div>}
    <form onSubmit={submit} className="new-assessment-layout">
      <div className="assessment-form-steps">
        <section className="card assessment-step-card" aria-labelledby="target-heading">
          <div className="assessment-step-heading"><span>1</span><div><div className="section-label">Assessment subject</div><h2 id="target-heading">Target MCP Endpoint</h2><p>Choose the MCP endpoint or saved metadata you want the report to evaluate.</p></div></div>
          <div className="assessment-step-content">
            <div className="field"><label className="label">Assessment source</label><div className="assessment-source-choices">
              <button type="button" className={`assessment-source-choice ${mode==="live"?"active":""}`} onClick={()=>{setMode("live");setUrl("")}}><span><Globe2 size={17}/></span><div><strong>Assess an endpoint</strong><small>Connect to a reachable MCP endpoint.</small></div><b>{mode==="live"?<><Check size={12}/> Selected</>:"Choose"}</b></button>
              <button type="button" className={`assessment-source-choice ${mode==="offline"?"active":""}`} onClick={()=>{setMode("offline");setUrl("")}}><span><FileJson2 size={17}/></span><div><strong>Use saved metadata</strong><small>Prepare a report without contacting a server.</small></div><b>{mode==="offline"?<><Check size={12}/> Selected</>:"Choose"}</b></button>
              <Link href="/directory" className="assessment-source-choice secondary"><span><Library size={17}/></span><div><strong>Review public reports</strong><small>Explore completed MCP assessments.</small></div><b>Browse <ArrowRight size={11}/></b></Link>
            </div></div>
            {mode==="offline"?<>
              <div className="field"><label className="label" htmlFor="snapshot-file">MCP metadata file</label><label className="snapshot-drop assessment-file-drop" htmlFor="snapshot-file"><Upload size={22}/><strong>{snapshot?snapshot.name:"Choose a JSON file"}</strong><span>{snapshot?`${snapshot.tools.length} tool contracts ready for assessment`:"Include tool descriptions, schemas, prompts, resources, or server instructions."}</span></label><input id="snapshot-file" className="sr-only" type="file" accept="application/json,.json" onChange={e=>{const file=e.target.files?.[0];if(file)void loadSnapshot(file)}}/></div>
              <div className="field"><label className="label" htmlFor="target-url">Original endpoint URL <span className="muted">(optional)</span></label><input id="target-url" type="url" className="input" placeholder="https://mcp.example.com/mcp" value={url} onChange={e=>setUrl(e.target.value)}/><p className="field-help">Reusing the endpoint in later reports enables catalog-change comparisons.</p></div>
              <div className="assessment-inline-note"><FileJson2 size={15}/><span><strong>File-only assessment</strong>The original server is not contacted. Live connection and authentication checks will be marked as not assessed.</span></div>
            </>:<>
              <div className="field"><label className="label" htmlFor="target-url">MCP endpoint URL</label><input id="target-url" required type="url" className="input assessment-url-input" placeholder="https://mcp.example.com/mcp" value={url} onChange={e=>{setUrl(e.target.value);setProfiles(items=>items.map(p=>({...p,oauth:undefined,connecting:false})))}}/><p className="field-help">Enter the Streamable HTTP endpoint provided by the MCP server.</p><details className="field-help connection-help"><summary>Using an endpoint on your computer?</summary><p>When Observatory runs in Docker, use <strong>http://host.docker.internal:PORT/mcp</strong>. Container-local localhost addresses are blocked by default.</p></details></div>
              <div className="assessment-inline-note safe"><ShieldCheck size={15}/><span><strong>Metadata-only connection</strong>Observatory discovers declared catalogs and contracts. It never executes discovered tools or sends fuzzing payloads.</span></div>
            </>}
          </div>
        </section>

        <section className="card assessment-step-card" aria-labelledby="identity-heading">
          <div className="assessment-step-heading"><span>2</span><div><div className="section-label">Access perspectives</div><h2 id="identity-heading">{mode==="offline"?"Report Inputs":"Identity Profiles"}</h2><p>{mode==="offline"?"The saved metadata will receive the same evidence-based analysis and reporting pipeline.":"Anonymous access is included automatically. Add identities only when you want to compare what different roles can discover."}</p></div></div>
          <div className="assessment-step-content">
            {mode==="offline"?<div className="offline-analysis-list">{["Capability classification","Contract and schema quality","Metadata integrity signals","Catalog change analysis","Downloadable readiness report"].map(label=><div key={label}><Check size={13}/>{label}</div>)}</div>:<>
              <div className="auth-methods" aria-label="Supported authentication methods">
                <div className="automatic"><Globe2 size={15}/><span><strong>Anonymous</strong>Included automatically</span></div>
                <div><KeyRound size={15}/><span><strong>Bearer Token</strong>Optional access token</span></div>
                <div><UserRoundCheck size={15}/><span><strong>OAuth</strong>Secure browser sign-in</span></div>
                <div><Network size={15}/><span><strong>Custom Headers</strong>For approved gateways</span></div>
              </div>
              <div className="identity-explanation"><Users size={16}/><div><strong>Why add more than one identity?</strong><p>Each profile is assessed in an isolated session. Comparing Reader, Writer, Administrator, or service identities reveals whether catalog visibility changes with access level—useful evidence for least-privilege readiness.</p></div></div>
              <div className="identity-profile-list">
                {profiles.map((profile,index)=><div className="credential-profile report-profile" key={profile.id}>
                  <div className="credential-heading"><div><div className="eyebrow">Optional identity {index+1}</div><strong>{profile.label||"Unnamed identity"}</strong></div>{profiles.length>1&&<button type="button" aria-label={`Remove ${profile.label||"profile"}`} className="button icon-button danger" onClick={()=>setProfiles(items=>items.filter(p=>p.id!==profile.id))}><Trash2 size={14}/></button>}</div>
                  <div className="field"><label className="label" htmlFor={`label-${profile.id}`}>Role or identity name</label><input id={`label-${profile.id}`} className="input" placeholder="Reader" value={profile.label} disabled={profile.oauth?.status==="authorized"} onChange={e=>update(profile.id,p=>({...p,label:e.target.value}))}/><p className="field-help">This label appears in the identity comparison within the report.</p></div>
                  <div className={`oauth-connect ${profile.oauth?.status==="authorized"?"connected":""}`}><span className="oauth-connect-icon">{profile.connecting?<LoaderCircle className="animate-spin" size={17}/>:profile.oauth?.status==="authorized"?<ShieldCheck size={17}/>:<RefreshCw size={17}/>}</span><div><strong>{profile.oauth?.status==="authorized"?"OAuth identity connected":"Connect with OAuth"}</strong><p>{profile.oauth?.status==="authorized"?`${profile.label} is ready for isolated metadata discovery.`:profile.oauth?.error||"Use the endpoint's authorization page for this identity."}</p>{profile.oauth&&profile.oauth.status!=="authorized"&&<StatusBadge value={profile.oauth.status}/>}</div>{profile.oauth?.status==="authorized"?<button type="button" title="Disconnect" aria-label={`Disconnect ${profile.label}`} className="button icon-button" onClick={()=>void disconnectOAuth(profile)}><X size={14}/></button>:<button type="button" className="button" disabled={profile.connecting||!url} onClick={()=>void connectOAuth(profile)}>{profile.connecting?<><LoaderCircle className="animate-spin" size={13}/>Connecting</>:<><ExternalLink size={13}/>Connect</>}</button>}</div>
                  <details className="manual-access" open={Boolean(profile.token||profile.headers.length)}><summary><span><KeyRound size={14}/>Use a bearer token or custom headers</span><small>Manual access details</small></summary><fieldset className="credential-fields" disabled={profile.oauth?.status==="authorized"}>
                    <div className="field"><label className="label" htmlFor={`token-${profile.id}`}>Bearer token</label><input id={`token-${profile.id}`} type="password" autoComplete="off" className="input" placeholder="Paste bearer token" value={profile.token} onChange={e=>update(profile.id,p=>({...p,token:e.target.value}))}/></div>
                    <label className="label">Custom headers</label>{profile.headers.map((header,headerIndex)=><div className="toolbar header-row" key={headerIndex}><input className="input" placeholder="Header name" aria-label={`Header ${headerIndex+1} name`} value={header.name} onChange={e=>update(profile.id,p=>({...p,headers:p.headers.map((h,i)=>i===headerIndex?{...h,name:e.target.value}:h)}))}/><input className="input" type="password" placeholder="Header value" aria-label={`Header ${headerIndex+1} value`} value={header.value} onChange={e=>update(profile.id,p=>({...p,headers:p.headers.map((h,i)=>i===headerIndex?{...h,value:e.target.value}:h)}))}/><button type="button" className="button icon-button danger" aria-label="Remove header" onClick={()=>update(profile.id,p=>({...p,headers:p.headers.filter((_,i)=>i!==headerIndex)}))}><Trash2 size={14}/></button></div>)}
                    <button className="button ghost" type="button" onClick={()=>update(profile.id,p=>({...p,headers:[...p.headers,{name:"",value:""}]}))}><Plus size={13}/> Add custom header</button>
                  </fieldset></details>
                </div>)}
              </div>
              <button disabled={profiles.length>=4} className="button add-identity-button" type="button" onClick={()=>setProfiles(items=>[...items,newProfile(nextProfileID.current++,["Writer","Administrator","Service account"][Math.min(items.length,2)])])}><Plus size={13}/> Add another identity <span>{profiles.length}/4</span></button>
              <div className="credential-privacy"><LockKeyhole size={14}/><span>Access details are encrypted for the assessment, excluded from evidence, and removed when processing ends.</span></div>
            </>}
          </div>
        </section>
      </div>

      <aside className="assessment-summary-column">
        <div className="card assessment-coverage-card">
          <div className="section-label">Your readiness report</div><h2>Assessment Coverage</h2><p>One assessment brings the observable MCP posture into a structured report.</p>
          <div className="assessment-coverage-list">
            <div><span><Network size={15}/></span><div><strong>Protocol &amp; metadata</strong><small>Discovery, transport, capabilities, prompts, and resources</small></div></div>
            <div><span><Braces size={15}/></span><div><strong>Contracts &amp; schemas</strong><small>Descriptions, annotations, constraints, and output declarations</small></div></div>
            <div><span><Fingerprint size={15}/></span><div><strong>Authentication &amp; identity</strong><small>OAuth posture and catalog visibility across access levels</small></div></div>
            <div><span><ShieldCheck size={15}/></span><div><strong>Operational readiness</strong><small>Context load, integrity signals, policy gaps, and catalog drift</small></div></div>
            <div><span><FileCheck2 size={15}/></span><div><strong>Evidence-based report</strong><small>Readiness scores, findings, and practical recommendations</small></div></div>
          </div>
          <div className="report-safety"><ShieldCheck size={15}/><span><strong>Zero tool execution</strong>Visibility is assessed without proving or attempting executability.</span></div>
          <button disabled={submitting} aria-busy={submitting} className="button primary start-assessment-button">{submitting?<><LoaderCircle className="animate-spin" size={15}/>Starting assessment…</>:<>Start Assessment <ArrowRight size={15}/></>}</button>
          <p className="assessment-submit-note">You can review progress as each report section is prepared.</p>
        </div>
      </aside>
    </form>
  </div>;
}
