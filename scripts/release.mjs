// Local preparation is the default. Remote commands require an explicit owner approval flag.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createRequire} from 'node:module';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {preflight} from './preflight.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const require=createRequire(import.meta.url);
const wrangler=()=>path.join(path.dirname(require.resolve('wrangler/package.json')),'bin','wrangler.js');
function run(args,cwd=root){const r=spawnSync(process.execPath,[wrangler(),...args],{cwd,stdio:'inherit',env:{...process.env,WRANGLER_SEND_METRICS:'false'}});if(r.status!==0)throw Error('Release step stopped; no automatic retry or rollback.');}
const read=p=>JSON.parse(fs.readFileSync(p,'utf8').replace(/^\uFEFF/,''));
const write=(p,v)=>fs.writeFileSync(p,JSON.stringify(v,null,2)+'\n');
const releaseRoot=fs.existsSync(path.join(root,'src'))?path.join(root,'release'):root;
const pages=path.join(releaseRoot,'pages'),worker=path.join(releaseRoot,'worker');
function sealArtifacts(){const files={};for(const f of fs.readdirSync(releaseRoot,{recursive:true}).sort()){if(f==='artifact-hashes.json'||f.split(path.sep).some(s=>s.startsWith('.')||s==='node_modules'))continue;const full=path.join(releaseRoot,f);if(fs.statSync(full).isFile())files[f.replaceAll('\\','/')]=createHash('sha256').update(fs.readFileSync(full)).digest('hex');}write(path.join(releaseRoot,'artifact-hashes.json'),files);}
const [action='help',...args]=process.argv.slice(2);
try {
 if(action==='prepare'){
  if(!fs.existsSync(path.join(root,'dist/index.html'))||!fs.existsSync(path.join(root,'src')))throw Error('Build the SOURCE package once before prepare.');
  if(fs.existsSync(path.join(root,'.dev.vars'))||fs.existsSync(path.join(root,'storage-worker/.dev.vars')))throw Error('Move local test secrets out of the workspace before release preparation.');
  fs.mkdirSync(pages,{recursive:true});fs.mkdirSync(worker,{recursive:true});
  fs.cpSync(path.join(root,'dist'),pages,{recursive:true});
  run(['pages','functions','build','functions','--outdir',path.join(pages,'_worker.js'),'--output-routes-path',path.join(pages,'_routes.json'),'--minify']);
  if(!args.includes('--pages-only'))run(['deploy','--config','storage-worker/wrangler.jsonc','--dry-run','--outdir',worker]);
  const p=read(path.join(root,'wrangler.jsonc'));p.pages_build_output_dir='.';delete p.$schema;
  // Preview fails closed until separate preview KV and Worker resources are explicitly configured.
  p.env={preview:{kv_namespaces:[],durable_objects:{bindings:[]}}};write(path.join(pages,'wrangler.jsonc'),p);
  const w=read(path.join(root,'storage-worker/wrangler.jsonc'));w.main='index.js';w.no_bundle=true;write(path.join(worker,'wrangler.jsonc'),w);
  write(path.join(pages,'release.json'),{product:'CHALAK PERFORMANCE V7 FINAL',version:'7.0.0',protocolVersion:2,authority:'chalak-authoritative-state-v1'});
  for(const d of ['scripts','tools'])fs.mkdirSync(path.join(releaseRoot,d),{recursive:true});
  for(const name of ['release.mjs','preflight.mjs'])fs.copyFileSync(path.join(root,'scripts',name),path.join(releaseRoot,'scripts',name));
  fs.copyFileSync(path.join(root,'tools/state-transfer.mjs'),path.join(releaseRoot,'tools/state-transfer.mjs'));
  for(const name of ['V7-READ-ME-FIRST.md','V7-CUTOVER.md'])if(fs.existsSync(path.join(root,name)))fs.copyFileSync(path.join(root,name),path.join(releaseRoot,name));
  for(const name of ['package.json','package-lock.json'])if(fs.existsSync(path.join(root,'scripts/deployment-'+name)))fs.copyFileSync(path.join(root,'scripts/deployment-'+name),path.join(releaseRoot,name));
  sealArtifacts();
  console.log('Pages Functions and SQLite Worker prepared locally. No deployment performed.');
 }else if(action==='seal-artifacts'){
  sealArtifacts();console.log('Local release artifact inventory updated; no remote action performed.');
 }else if(action==='verify'){
  const files=read(path.join(releaseRoot,'artifact-hashes.json'));for(const [f,hash]of Object.entries(files)){if(createHash('sha256').update(fs.readFileSync(path.join(releaseRoot,f))).digest('hex')!==hash)throw Error('Artifact checksum mismatch: '+f);}
  const p=read(path.join(pages,'wrangler.jsonc')),w=read(path.join(worker,'wrangler.jsonc'));
  if(p.durable_objects?.bindings?.[0]?.script_name!==w.name||p.durable_objects.bindings[0].class_name!=='ChalakState'||!w.migrations?.some(m=>m.new_sqlite_classes?.includes('ChalakState')))throw Error('Two-service binding/migration mismatch');
  if(!fs.existsSync(path.join(pages,'_worker.js/index.js'))||!fs.existsSync(path.join(worker,'index.js')))throw Error('Compiled backend missing');
  if((p.env?.preview?.durable_objects?.bindings||[]).some(b=>b.script_name===w.name))throw Error('Preview must not share the Production authority');
  console.log('Artifact hashes, compiled Functions, Worker and SQLite configuration verified locally.');
 }else if(action==='preflight'){
  console.log(JSON.stringify(await preflight({pages,worker,phase:'pages'}),null,2));
 }else if(action==='deploy-worker'||action==='deploy-pages'){
  if(!args.includes('--owner-approved'))throw Error('Owner approval required; no deployment performed.');
  if(process.env.CHALAK_LEGACY_WRITES_FROZEN!=='YES')throw Error('Freeze and verify ALL legacy write routes first; no deployment performed.');
  const files=read(path.join(releaseRoot,'artifact-hashes.json'));for(const [f,hash]of Object.entries(files))if(createHash('sha256').update(fs.readFileSync(path.join(releaseRoot,f))).digest('hex')!==hash)throw Error('Artifact changed; stop deployment and review '+f);
  const result=await preflight({pages,worker,phase:action==='deploy-worker'?'worker':'pages'});
  if(!result.ok){console.log(JSON.stringify(result,null,2));throw Error('Live configuration gate BLOCKED; no deployment performed.');}
  if(action==='deploy-worker')run(['deploy','--config','wrangler.jsonc','--keep-vars'],worker);
  else run(['pages','deploy','.','--project-name',result.project,'--branch',result.productionBranch,'--commit-message','CHALAK PERFORMANCE V7 FINAL'],pages);
  console.log('Deployment command completed. Writes remain gated until verified migration and owner-approved smoke check.');
 }else console.log('SOURCE: node scripts/release.mjs prepare\nBOTH PACKAGES: node scripts/release.mjs verify | preflight | deploy-worker --owner-approved | deploy-pages --owner-approved\nMigration/cutover are separate operator steps; never automatic.');
}catch(e){console.error(e instanceof Error?e.message:'Release step failed');process.exitCode=1;}
