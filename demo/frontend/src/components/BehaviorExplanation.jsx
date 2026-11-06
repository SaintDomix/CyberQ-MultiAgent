import React,{useState} from 'react';
import {Badge,Tabs} from './UI.jsx';
import {format} from '../utils/data.js';

function Factors({factors}){
 const value=(v,unit)=>unit==='fraction'?`${format(v*100,1)}%`:`${format(v,4)} ${unit??''}`;
 return factors?.length?<ul>{factors.map(f=><li key={f.factor_id}>{f.human_text}
  <dl className="meta-grid"><div><dt>Observed</dt><dd>{value(f.observation,f.unit)}</dd></div><div><dt>Benign TRAIN median</dt><dd>{value(f.reference,f.unit)}</dd></div><div><dt>Comparison / direction</dt><dd>{f.comparison} · {f.direction}</dd></div>{f.model_contribution!=null&&<div><dt>Selected-class margin contribution</dt><dd>{format(f.model_contribution,5)}</dd></div>}</dl>
  {f.windows_observed!=null&&<small>Feature reported in {f.windows_observed} linked window(s); numeric values describe representative observation {f.representative_observation_id}.</small>}</li>)}</ul>:<p className="muted">Insufficient supported evidence for primary factors. Technical model outputs remain available.</p>;
}

export function BehaviorExplanation({observation}){
 const [tab,setTab]=useState('summary');
 const e=observation.explanation;
 if(!e?.anomaly||!e?.classification)return <p className="note">Human-readable interpretation unavailable for this record. Technical evidence remains below. Reason: <strong>{e?.evidence_quality?.reason_code??'LEGACY_API_EXPLANATION_PAYLOAD'}</strong>{!e?.evidence_quality?.reason_code&&' · Reload the demo backend to load the current explanation contract.'}</p>;
 const normal=observation.reconciled_label==='BENIGN';
 return <section aria-label="Human-readable behavioral explanation">
  <h3>{normal?'WHY DOES THIS WINDOW APPEAR NORMAL?':observation.reconciled_label==='UNCERTAIN'?'WHY IS THIS WINDOW UNCERTAIN?':'WHY WAS THIS WINDOW FLAGGED?'}</h3>
  <Tabs label="Observation explanation" value={tab} onChange={setTab} items={[["summary","Summary"],["factors","Important factors"]]}/>
  <div hidden={tab!=='summary'}><p>{e.summary}</p><ul className="primary-factors">{e.anomaly.factors?.slice(0,3).map(f=><li key={f.factor_id}>{f.human_text}</li>)}</ul><p>Novelty: <strong>{e.anomaly.verdict}</strong> · classifier observation: <strong>{e.classification.display_label}</strong> · score {format(e.classification.score,5)} (uncalibrated).</p>{observation.reconciled_label==='UNKNOWN_ANOMALY'&&<p className="note">No supported known class was established by reconciliation. The classifier observation is retained for inspection.</p>}<p className="muted">Observation ≠ incident. Inspect Factors for original observed and benign-reference values.</p></div>
  <div hidden={tab!=='factors'}><h4>{normal?'Behavior compared with the benign reference':'Behavior deviation'}</h4>
  <Badge>{e.anomaly.verdict}</Badge><Factors factors={e.anomaly.factors}/>
  <p className="muted">{e.anomaly.interpretation}</p>
  <h4>Attack classification</h4><Badge>{e.classification.display_label}</Badge>
  {observation.reconciled_label==='UNKNOWN_ANOMALY'&&<p className="note">No known attack class was established by frozen reconciliation. The highest-scoring classifier class is shown as a model observation{e.classification.accepted_confidence_threshold!=null?`; the uncalibrated score is compared with the unchanged ${format(e.classification.accepted_confidence_threshold,2)} threshold`:''}.</p>}
  <h4>{normal?'Evidence for the BENIGN class':'Why this class'}</h4>
  <Factors factors={e.classification.factors}/>
  <h4>Model evidence</h4><p>OCSVM: {e.anomaly.verdict} · score {format(e.anomaly.score,6)}. XGBoost: {e.classification.display_label} · uncalibrated class score {format(e.classification.score,5)}.</p>
  {e.anomaly.threshold!=null&&<p className="muted">Frozen OCSVM cutoff: {format(e.anomaly.threshold,6)}. A score below the cutoff is anomalous; it is not an attack probability.</p>}
  <p className="muted">{e.classification.score_semantics}</p>
  {observation.model_disagreement&&<p className="note">MODEL DISAGREEMENT: novelty and known-class evidence differ. The recorded reconciliation and incident decision are unchanged.</p>}
  <p className="muted">Reference coverage: {e.evidence_quality?.available_features??0}/83 features · SHAP: {e.evidence_quality?.shap_status??'UNAVAILABLE'}</p>
  <p className="method-note">{e.evidence_quality?.limitation}</p></div>
 </section>;
}

export function IncidentExplanation({incident}){
 const e=incident.explanation;
 if(!e?.version)return null;
 return <section aria-label="Episode explanation"><h3>Why this episode exists</h3><p>{e.summary}</p>
  <p>{e.anomalous_windows}/{e.linked_window_count} linked windows were anomalous. Dominant classifier class: {e.dominant_classifier_class?.replaceAll('_',' ')??'Unavailable'}.</p>
  <p>{e.persistence_semantics}</p><h4>Representative evidence across the episode</h4>
  <Factors factors={e.representative_factors}/><p className="method-note">Observation ≠ incident. Multiple windows can belong to one attempt-pattern episode.</p>
 </section>;
}
