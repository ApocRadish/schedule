// Синхронизация графика: хранит только зашифрованные снимки, ключ шифрования сюда не попадает.
const H={'access-control-allow-origin':'*','access-control-allow-methods':'GET,PUT,OPTIONS','access-control-allow-headers':'content-type,x-write-key','cache-control':'no-store'};
const res=(b,s=200)=>new Response(b,{status:s,headers:H});
async function sha(t){const d=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(t));return [...new Uint8Array(d)].map(x=>x.toString(16).padStart(2,'0')).join('')}
const TTL=60*60*24*120;
export default{async fetch(req,env){
  if(req.method==='OPTIONS')return res(null,204);
  const m=new URL(req.url).pathname.match(/^\/s\/([a-f0-9]{32})$/);
  if(!m)return res('ok');
  const k='s:'+m[1];
  if(req.method==='GET'){const v=await env.SYNC.get(k);return v?res(v):res('not found',404)}
  if(req.method==='PUT'){
    const wk=req.headers.get('x-write-key')||'';if(wk.length<16)return res('bad key',401);
    const body=await req.text();if(!body||body.length>200000)return res('bad size',413);
    const h=await sha(wk),cur=await env.SYNC.get(k+':h');
    if(cur&&cur!==h)return res('forbidden',403);
    if(!cur)await env.SYNC.put(k+':h',h,{expirationTtl:TTL});
    await env.SYNC.put(k,body,{expirationTtl:TTL});return res('saved')}
  return res('method not allowed',405)}};
