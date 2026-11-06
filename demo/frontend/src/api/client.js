export async function api(path,options={}){
 const response=await fetch('/api/'+path,{cache:'no-store',...options});
 const body=await response.json();
 if(!response.ok){const error=Error(body.message||body.error||body.detail?.message||(typeof body.detail==='string'?body.detail:null)||'Application service unavailable');error.status=response.status;throw error;}
 return body;
}
export const control=action=>api('runtime/'+action,{method:'POST',headers:{'Content-Type':'application/json','X-Product-Control':'1'},body:'{}'});
export const selectMode=mode=>api('demo/mode',{method:'POST',headers:{'Content-Type':'application/json','X-Product-Control':'1'},body:JSON.stringify({mode})});
