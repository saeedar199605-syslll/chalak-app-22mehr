// Read-only REST inspection. Credentials and secret values are never logged or written.
import fs from 'node:fs';
import {isDeepStrictEqual} from 'node:util';
const read=p=>JSON.parse(fs.readFileSync(p,'utf8').replace(/^\uFEFF/,''));
const sorted=o=>Object.fromEntries(Object.entries(o||{}).sort(([a],[b])=>a.localeCompare(b)));
export async function preflight({pages,worker,phase}){
 const account=process.env.CLOUDFLARE_ACCOUNT_ID,project=process.env.CHALAK_PAGES_PROJECT,token=process.env.CLOUDFLARE_API_TOKEN;
 if(!account||!project||!token)throw Error('Read-only live preflight requires CLOUDFLARE_ACCOUNT_ID, CHALAK_PAGES_PROJECT and a private CLOUDFLARE_API_TOKEN. Never put the token in release files.');
 const p=read(pages+'/wrangler.jsonc'),w=read(worker+'/wrangler.jsonc');
 async function get(suffix,optional=false,withInfo=false){const r=await fetch('https://api.cloudflare.com/client/v4/accounts/'+encodeURIComponent(account)+suffix,{headers:{Authorization:'Bearer '+token},signal:AbortSignal.timeout(20000)});if(optional&&r.status===404)return null;if(!r.ok)throw Error('Read-only Cloudflare inspection failed: HTTP '+r.status);const b=await r.json();if(!b.success)throw Error('Cloudflare inspection not accepted; configuration remains unverified.');return withInfo?{data:b.result,info:b.result_info}:b.result;}
 const identity=await get('');if(identity.id!==account)throw Error('Account identity mismatch');
 const live=await get('/pages/projects/'+encodeURIComponent(project));
 if(live.name!==p.name||live.name!==project)throw Error('Actual Pages project differs from reviewed configuration.');
 const problems=[],plannedAdditions=[],expectedKV=p.kv_namespaces.find(b=>b.binding==='CHALAK_DB')?.id;
 const namespaces=[];let complete=false;
 for(let page=1;page<=100;page++){const chunk=await get('/workers/durable_objects/namespaces?per_page=100&page='+page,false,true);namespaces.push(...chunk.data);if(page>=(chunk.info?.total_pages||1)){complete=true;break;}}
 if(!complete)throw Error('Namespace inventory incomplete; no deployment allowed');
 function environment(label,config,actual){
  if(!actual){problems.push(label+': configuration unavailable');return;}
  const kv=Object.fromEntries((config.kv_namespaces||[]).map(b=>[b.binding,{namespace_id:b.id}]));
  if(!isDeepStrictEqual(sorted(kv),sorted(actual.kv_namespaces)))problems.push(label+': KV bindings differ; preserve/review existing bindings');
  const intended=config.durable_objects?.bindings||[],got=actual.durable_object_namespaces||{};
  if(Object.keys(got).some(name=>!intended.some(b=>b.name===name)))problems.push(label+': existing DO binding would be removed');
  for(const b of intended){
   if(!got[b.name]){if(b.name==='CHALAK_STATE'&&label==='Production')plannedAdditions.push(label+': CHALAK_STATE binding will be added only during approved cutover');else problems.push(label+': DO binding missing');continue;}
   const ns=namespaces.find(n=>n.id===got[b.name].namespace_id);
   if(!ns||ns.script!==b.script_name||ns.class!==b.class_name||ns.use_sqlite!==true)problems.push(label+': actual DO namespace/Worker/class/SQLite differs');
  }
  const plain=Object.fromEntries(Object.entries(actual.env_vars||{}).filter(([,v])=>v.type==='plain_text').map(([k,v])=>[k,v.value]));
  if(!isDeepStrictEqual(sorted(config.vars),sorted(plain)))problems.push(label+': existing plain vars need a reviewed configuration; values are not printed');
  for(const key of ['d1_databases','r2_buckets','services','queue_producers','analytics_engine_datasets','ai_bindings','vectorize_bindings','hyperdrive_bindings','mtls_certificates','browsers'])if(actual[key]&&Object.keys(actual[key]).length)problems.push(label+': additional '+key+' binding requires explicit preservation in reviewed config');
  if(label==='Production'&&!Object.entries(actual.env_vars||{}).some(([k,v])=>k==='ADMIN_PASSWORD'&&v.type==='secret_text'))problems.push('Production: ADMIN_PASSWORD name not present; confirm credential-only login separately before overriding this gate');
 }
 environment('Production',p,live.deployment_configs?.production);environment('Preview',p.env?.preview||{},live.deployment_configs?.preview);
 const preview=p.env?.preview||{};
 if((preview.durable_objects?.bindings||[]).some(b=>b.script_name===w.name)||(preview.kv_namespaces||[]).some(b=>b.id===expectedKV))problems.push('Preview shares Production storage; separate resources required');
 const settings=await get('/workers/scripts/'+encodeURIComponent(w.name)+'/settings',true);
 if(settings){
  const own=namespaces.find(n=>n.script===w.name&&n.class==='ChalakState');
  if(!own||own.use_sqlite!==true)problems.push('SQLite namespace not proven by Cloudflare namespace metadata');
  const bindings=settings.bindings||[];
  if(bindings.some(b=>!['CHALAK_DB','CHALAK_STATE'].includes(b.name)&&b.type!=='secret_text'&&b.type!=='plain_text'))problems.push('Existing Worker extra bindings require explicit preservation');
  if(bindings.find(b=>b.name==='CHALAK_DB')?.namespace_id!==expectedKV)problems.push('Worker KV namespace differs');
  if(phase!=='worker'&&!bindings.some(b=>b.name==='STORAGE_MAINTENANCE_TOKEN'&&b.type==='secret_text'))problems.push('Worker: STORAGE_MAINTENANCE_TOKEN name missing');
  const service=await get('/workers/services/'+encodeURIComponent(w.name));
  if(service.default_environment?.script?.migration_tag!==w.migrations.at(-1).tag)problems.push('Worker migration tag differs');
 }else if(phase!=='worker')problems.push('Dedicated Worker not deployed yet');
 const secretNames=e=>Object.entries(e?.env_vars||{}).filter(([,v])=>v.type==='secret_text').map(([name])=>name).sort();
 return {ok:problems.length===0,accountId:account,accountName:identity.name,project:live.name,productionBranch:live.production_branch,worker:w.name,workerExists:!!settings,secretNames:{production:secretNames(live.deployment_configs?.production),preview:secretNames(live.deployment_configs?.preview),worker:(settings?.bindings||[]).filter(b=>b.type==='secret_text').map(b=>b.name).sort()},plannedAdditions,problems,liveConfigurationChecked:true};
}
