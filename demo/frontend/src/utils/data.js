export const format=(v,d=2)=>typeof v==='number'&&Number.isFinite(v)?v.toFixed(d):'—';
export const human=v=>(v||'Unavailable').replaceAll('_',' ');
export const time=v=>v?new Date(v).toLocaleTimeString('en-GB',{timeZone:'UTC',hour12:false}):'—';
export const stamp=v=>v?new Date(v).toLocaleString('en-GB',{timeZone:'UTC',hour12:false})+' UTC':'Unavailable';
export const kind=v=>v==='BENIGN'?'benign':v==='UNKNOWN_ANOMALY'?'anomaly':v==='UNCERTAIN'?'uncertain':'attempt';
export const dimensionNames={D1:'Transport & HTTP Protection',D2:'Identity, Session & Access',D3:'Exposure & Disclosure',D4:'Patch & Vulnerability Management',D5:'Server Hardening & Integrity',D6:'Behavioral Threat Activity'};
export const recommendationPriority=(rec,drivers)=>Math.max(0,...drivers.filter(d=>rec.evidence_ids?.some(id=>d.member_evidence_ids?.includes(id)||id===d.representative_evidence?.evidence_id)).map(d=>d.contribution));
