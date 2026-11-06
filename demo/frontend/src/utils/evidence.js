// Display selection only. Never change canonical membership, hazard or CQI.
const severityOrder={INFO:0,LOW:1,MEDIUM:2,HIGH:3,CRITICAL:4};
export function findingDisplayTitle(finding){
 const title=finding.title||finding.finding_type||finding.finding_id;
 const status=finding.status||finding.check_result;
 const observed=finding.observed_value||finding.evidence?.observation?.observed;
 // This is a control label, not a description of its failed result. Require
 // explicit retained HTTP evidence; an HTTP URL alone does not disprove HTTPS.
 if(finding.finding_id==='TLS-001'&&status==='FAIL'&&title==='HTTPS enabled'&&
    (observed==='Target uses HTTP'||finding.description==='The assessed target is served over unencrypted HTTP.'))
  return 'Assessed target uses unencrypted HTTP';
 return title;
}
export function representativeForRoot(root,posture){
 const members=(root.members||[]).filter(m=>Number.isFinite(m.hazard)&&m.hazard>0);
 const ordered=[...members].sort((a,b)=>(severityOrder[b.severity]??-1)-(severityOrder[a.severity]??-1)||b.hazard-a.hazard||String(a.finding_id).localeCompare(String(b.finding_id)));
 const member=ordered[0];if(!member)return null;
 const finding=posture.find(f=>f.finding_id===member.finding_id||f.provenance?.evidence_id===member.source_id||f.member_evidence_ids?.includes(member.source_id));
 // The same control ID can have different scanner members. Only exact source
 // identity may supply a member title; never join it to another member's severity.
 const raw=finding?.evidence_summary?.members?.find(m=>m.evidence_id===member.source_id||m.provenance?.evidence_id===member.source_id);
 const sameFinding=finding&&finding.finding_id===member.finding_id&&finding.severity===member.severity&&finding.confirmation===member.confirmation;
 const sourceTitle=raw?.finding_type||raw?.title||(sameFinding?finding.title:member.finding_id);
 return {...member,title:findingDisplayTitle({...(sameFinding?finding:{}),...raw,title:sourceTitle,finding_id:member.finding_id,status:member.status}),source_title:sourceTitle,
  evidence_id:member.source_id||finding?.finding_id||member.finding_id,
  root_id:root.root_id,member_count:(root.members||[]).length,
  semantics:'Most severe supported member; title, severity and verification refer to the same evidence member.'};
}
export function supportedPostureRoots(data){
 return data.scientific_cqi.contributors.filter(c=>c.dimension!=='D6'&&c.hazard>0)
  .map(root=>({root,representative:representativeForRoot(root,data.posture)})).filter(x=>x.representative)
  .sort((a,b)=>b.root.hazard-a.root.hazard||a.root.root_id.localeCompare(b.root.root_id));
}
