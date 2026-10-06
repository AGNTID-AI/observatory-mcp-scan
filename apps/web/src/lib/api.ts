import type { Assessment, AssessmentSummary, DashboardSummary, OAuthSession, OfflineSnapshot, Rule } from "./types";

async function request<T>(path:string, init?:RequestInit):Promise<T> {
  const response=await fetch(`/api/v1${path}`,{...init,headers:{"Content-Type":"application/json",...(init?.headers||{})},cache:"no-store"});
  if(!response.ok){const problem=await response.json().catch(()=>({detail:response.statusText}));throw new Error(problem.detail||problem.title||"Request failed")}
  return response.json() as Promise<T>;
}

export const api = {
  dashboard:()=>request<DashboardSummary>("/dashboard/summary"),
  assessments:()=>request<{items:AssessmentSummary[]}>("/assessments?limit=100"),
  assessment:async(id:string)=>normalizeAssessment(await request<Assessment>(`/assessments/${id}`)),
  create:(body:{mode:"live"|"sample"|"offline";target:{protocol:"mcp";url:string};credentials?:{bearerToken?:string;headers?:Record<string,string>};credentialProfiles?:Array<{label:string;bearerToken?:string;headers?:Record<string,string>;oauthSessionId?:string}>;snapshot?:OfflineSnapshot})=>request<{assessmentId:string;status:string;eventsUrl:string}>("/assessments",{method:"POST",body:JSON.stringify(body)}),
  startOAuth:(targetUrl:string,label:string)=>request<OAuthSession>("/oauth/sessions",{method:"POST",body:JSON.stringify({targetUrl,label})}),
  oauthSession:(id:string)=>request<OAuthSession>(`/oauth/sessions/${encodeURIComponent(id)}`),
  cancelOAuth:(id:string)=>request<{status:string}>(`/oauth/sessions/${encodeURIComponent(id)}/cancel`,{method:"POST"}),
  cancel:(id:string)=>request<{status:string}>(`/assessments/${id}/cancel`,{method:"POST"}),
  rules:()=>request<{items:Rule[]}>("/rules"),
  settings:()=>request<Record<string,unknown>>("/settings"),
};

export function artifactURL(assessmentId:string, artifactId:string){return `/api/v1/assessments/${assessmentId}/artifacts/${encodeURIComponent(artifactId)}`}

function normalizeAssessment(value:Assessment):Assessment {
  const emptyRisk={critical:0,high:0,medium:0,low:0,info:0};
  const emptyContext={toolTokens:0,promptTokens:0,resourceTokens:0,instructionTokens:0,totalTokens:0,contextWindow:128000,utilization:0,estimator:"unavailable"};
  const tools=(value.tools??[]).map(tool=>({...tool,categories:tool.categories??[],visibleTo:tool.visibleTo??[],annotations:tool.annotations??{},classification:{taxonomyVersion:tool.classification?.taxonomyVersion??0,classifierRevision:tool.classification?.classifierRevision??"legacy",operationType:tool.classification?.operationType??tool.categories?.[0]??"unknown",domain:tool.classification?.domain??"unknown",blastRadius:tool.classification?.blastRadius??"unknown",sensitivity:tool.classification?.sensitivity??"unknown",criticality:tool.classification?.criticality??"unknown",privilegeLevel:tool.classification?.privilegeLevel??0,isMutating:tool.classification?.isMutating??false,isDiscover:tool.classification?.isDiscover??false,executionSurface:tool.classification?.executionSurface??"unknown",effects:tool.classification?.effects??[],confidenceBand:tool.classification?.confidenceBand??"unknown",perDimensionConfidence:tool.classification?.perDimensionConfidence??{},evidence:tool.classification?.evidence??[],annotationContradictions:tool.classification?.annotationContradictions??[]},schema:{valid:tool.schema?.valid??false,hasOutputSchema:tool.schema?.hasOutputSchema??false,additionalProperties:tool.schema?.additionalProperties??"unknown",propertyCount:tool.schema?.propertyCount??0,requiredCount:tool.schema?.requiredCount??0,describedPropertyCount:tool.schema?.describedPropertyCount??0,descriptionCoverage:tool.schema?.descriptionCoverage??0,maxDepth:tool.schema?.maxDepth??0,unconstrainedStringCount:tool.schema?.unconstrainedStringCount??0,sensitiveFields:tool.schema?.sensitiveFields??[],dangerousFields:tool.schema?.dangerousFields??[],inputRisks:tool.schema?.inputRisks??[],signals:tool.schema?.signals??[]},policyPreview:tool.policyPreview??{}}));
  const findings=(value.findings??[]).map(finding=>({...finding,classification:finding.classification||"posture",evidenceIds:finding.evidenceIds??[],toolNames:finding.toolNames??finding.replay?.toolNames??[],replay:finding.replay?{...finding.replay,toolNames:finding.replay.toolNames??[]}:undefined}));
  return {
    ...value,
    engineRuns:value.engineRuns??[], findings, evidence:value.evidence??[],
    recommendations:value.recommendations??[], artifacts:value.artifacts??[], tools,
    identityExposure:{profiles:value.identityExposure?.profiles??[],tools:value.identityExposure?.tools??[],comparedProfiles:value.identityExposure?.comparedProfiles??0,catalogEquivalent:value.identityExposure?.catalogEquivalent??false,privilegeSeparationObserved:value.identityExposure?.privilegeSeparationObserved??false,anonymousToolCount:value.identityExposure?.anonymousToolCount??0,notes:value.identityExposure?.notes??[]},
    policySimulation:{profiles:value.policySimulation?.profiles??[],generated:value.policySimulation?.generated??false,disclaimer:value.policySimulation?.disclaimer??""},riskChains:value.riskChains??[],
    contentInventory:value.contentInventory??[],
    contentIntegrity:{itemsScanned:value.contentIntegrity?.itemsScanned??0,signals:value.contentIntegrity?.signals??[],bySeverity:value.contentIntegrity?.bySeverity??{},disclaimer:value.contentIntegrity?.disclaimer??""},
    readiness:{tools:value.readiness?.tools??[],averageScore:value.readiness?.averageScore??0,coverage:value.readiness?.coverage??0,disclaimer:value.readiness?.disclaimer??""},
    catalogDrift:{compared:value.catalogDrift?.compared??false,stable:value.catalogDrift?.stable??false,added:value.catalogDrift?.added??0,removed:value.catalogDrift?.removed??0,modified:value.catalogDrift?.modified??0,changes:value.catalogDrift?.changes??[],baselineAssessmentId:value.catalogDrift?.baselineAssessmentId,baselineAt:value.catalogDrift?.baselineAt,previousFingerprint:value.catalogDrift?.previousFingerprint,currentFingerprint:value.catalogDrift?.currentFingerprint,disclaimer:value.catalogDrift?.disclaimer??""},
    oauth:{status:value.oauth?.status??"not-assessed",protected:value.oauth?.protected??false,challengePresent:value.oauth?.challengePresent??false,resourceMetadataValid:value.oauth?.resourceMetadataValid??false,authorizationServers:value.oauth?.authorizationServers??[],authorizationServerMetadataValid:value.oauth?.authorizationServerMetadataValid??false,dcrSupported:value.oauth?.dcrSupported??false,clientIdMetadataDocumentSupported:value.oauth?.clientIdMetadataDocumentSupported??false,pkceS256:value.oauth?.pkceS256??false,scopes:value.oauth?.scopes??[],bearerMethods:value.oauth?.bearerMethods??[],headerBearerSupported:value.oauth?.headerBearerSupported??false,authorizationCompleted:value.oauth?.authorizationCompleted??false,registrationMethod:value.oauth?.registrationMethod,authorizedIdentities:value.oauth?.authorizedIdentities??[],diagnostics:value.oauth?.diagnostics??[],resourceMetadataUrl:value.oauth?.resourceMetadataUrl,resource:value.oauth?.resource,issuer:value.oauth?.issuer,authorizationEndpoint:value.oauth?.authorizationEndpoint,tokenEndpoint:value.oauth?.tokenEndpoint,registrationEndpoint:value.oauth?.registrationEndpoint,assessedAt:value.oauth?.assessedAt},
    risk:value.risk??emptyRisk,
    server:value.server??{authentication:"not-assessed",authorization:"not-assessed",tls:"not-assessed",toolCount:0,promptCount:0,resourceCount:0},
    context:value.context??emptyContext,
    scorecard:{overall:value.scorecard?.overall??0,coverage:value.scorecard?.coverage??0,dimensions:value.scorecard?.dimensions??{}},
  };
}
