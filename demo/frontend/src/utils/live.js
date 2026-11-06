export function controlState(status,busy=false){const jobs=status?.jobs||{};const posture=jobs.posture?.status==='RUNNING',live=jobs.live?.status==='RUNNING',running=posture||live;return {running,full:!busy&&!running,posture:!busy&&!running,live:!busy&&!running&&status?.state!=='STOPPED'};}
export function predictionDelta(previous,current){return previous?.session_id===current?.session_id?Math.max(0,(current?.prediction_count||0)-(previous?.prediction_count||0)):0;}
export function currentSelection(selected,records){return records.some(r=>r.sequence===selected)?selected:(records.at(-1)?.sequence??null);}
export function recoveredMode(status){return Object.values(status?.jobs||{}).some(j=>j.status==='RUNNING')?'LIVE_LAB':'ACCEPTED_REPLAY';}
