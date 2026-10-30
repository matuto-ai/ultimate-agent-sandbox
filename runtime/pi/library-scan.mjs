// Pi-local native bash recipe, not a tool/service or cross-Runtime protocol.
// No path/environment selector in the executable entry point.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const clean = value => String(value).replace(/[\x00-\x1f\x7f]/g, ' ').slice(0,240);
const fold = value => value.normalize('NFC').toLowerCase();
function near(a,b) {
  if(a===b)return true;
  if(a.length<4 || b.length<4 || Math.abs(a.length-b.length)>1)return false;
  let i=0,j=0,edits=0;
  while(i<a.length && j<b.length) {
    if(a[i]===b[j]) {i++;j++;continue;}
    if(++edits>1)return false;
    if(a.length>=b.length)i++;
    if(b.length>=a.length)j++;
  }
  return edits+(i<a.length || j<b.length?1:0)<=1;
}
function metadata(text,parse,now) {
  const match=/^---\n([\s\S]*?)\n---(?:\n|$)/.exec(text);
  let m={},warning='';
  try {m=match?parse(match[1]):{};if(!m || typeof m!=='object' || Array.isArray(m))throw Error();}
  catch {m={};warning='metadata unreadable; open document';}
  const verified=Array.isArray(m.verified)?m.verified:m.verified?[m.verified]:[];
  const actors=verified.filter(v=>v && typeof v.by==='string' && v.by && typeof v.at==='string' && Number.isFinite(Date.parse(v.at)));
  const trust=actors.some(v=>/^human:.+/.test(v.by))?'human-reviewed':actors.length?'machine-confirmed':
    Object.hasOwn(m,'verified')?'unknown':'unverified';
  const date=typeof m.stale_after==='string'?m.stale_after:'';
  let freshness=Object.hasOwn(m,'stale_after')?'unknown':'no recorded policy';
  if(/^\d{4}-\d{2}-\d{2}$/.test(date) && Number.isFinite(Date.parse(date)) && new Date(date).toISOString().slice(0,10)===date)
    freshness=now.slice(0,10)>=date?'STALE warning (still readable)':'within recorded policy';
  const sources=Array.isArray(m.sources)?(m.sources.length?'present':'absent'):Object.hasOwn(m,'sources')?'unknown':'absent';
  return {title:clean(m.title??'(untitled)'),type:clean(m.type??'unknown'),lifecycle:clean(m.status??'stable'),trust,
    freshness,sources,warning,body:match?text.slice(match[0].length):text};
}
function bytes(file,max) {
  const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  try {const s=fs.fstatSync(fd);if(!s.isFile()||s.size>max)throw Error();
    const data=fs.readFileSync(fd);if(data.length>max)throw Error();
    return new TextDecoder('utf-8',{fatal:true}).decode(data);
  }finally{fs.closeSync(fd);}
}
// Internal composition seam for disposable projection/native-tool checks.
// Production callers have only query words; this function is not a Runtime tool.
export function scan(reference,query,{parse,now=new Date().toISOString()}={}) {
  if(!Array.isArray(query)||!query.length||query.length>16||query.some(t=>typeof t!=='string'||!t.trim()||t.length>128))
    throw Error('query requires 1..16 nonempty bounded literal terms');
  const terms=query.map(t=>fold(t.trim()));
  try {
    const ref=fs.realpathSync(reference);
    const manifestFile=path.join(ref,'library.snapshot.json');
    const before=fs.readFileSync(manifestFile,'utf8');
    if(before.length>4096)throw Error();
    const manifest=JSON.parse(before);
    if(manifest.commit_sha===null)return 'Library has no published snapshot. No inferred answer.\n';
    if(!/^[0-9a-f]{40,64}$/.test(manifest.commit_sha))throw Error();
    const root=fs.realpathSync(path.join(ref,'library'));
    // T07 public symlink resolves only to its own selected immutable generation.
    const rel=path.relative(ref,root);
    if(!/^\.library-snapshots\/[0-9a-f]{32}\/library$/.test(rel))throw Error();
    const docs=[];let total=0,count=0;
    const walk=(directory,prefix='')=>{
      for(const entry of fs.readdirSync(directory,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name,'en'))) {
        if(entry.name.startsWith('.')||entry.isSymbolicLink())throw Error();
        const name=prefix+entry.name,full=path.join(directory,entry.name);
        if(entry.isDirectory())walk(full,name+'/');
        else {
          if(!entry.isFile()||++count>4096)throw Error();
          const text=bytes(full,1048576);total+=Buffer.byteLength(text);if(total>1048576)throw Error();
          if(name.endsWith('.md') && path.basename(name)!=='index.md' && name!=='log.md')
            docs.push({name,text,...metadata(text,parse,now)});
        }
      }
    };
    walk(root);
    let selected=docs.filter(d=>terms.every(t=>fold(d.text).includes(t))),fuzzy=false;
    if(!selected.length) {fuzzy=true;selected=docs.filter(d=>{
      const tokens=fold(d.text).match(/[\p{L}\p{N}_-]+/gu)||[];
      return terms.every(t=>tokens.some(w=>near(t,w)));
    });}
    const rows=[`Snapshot ${manifest.commit_sha}; published ${clean(manifest.published_at??'unknown')}. Reference data only.`];
    for(const d of selected.slice(0,8)) {
      const draft=d.name.startsWith('pending/')||d.lifecycle==='draft';
      const lines=d.body.split('\n');
      const line=lines.find(l=>terms.some(t=>fuzzy?(fold(l).match(/[\p{L}\p{N}_-]+/gu)||[]).some(w=>near(t,w)):fold(l).includes(t)))
        ??lines.find(l=>l.trim())??'';
      rows.push(`\n${fuzzy?'FUZZY ':''}${draft?'DRAFT ':''}${clean(d.name)} — ${d.title}`,
        `fragment: ${clean(line)}`,
        `type: ${d.type}; lifecycle: ${d.lifecycle}; trust tier: ${d.trust}; freshness: ${d.freshness}; sources: ${d.sources}`,
        ...(d.warning?[d.warning]:[]));
    }
    if(!selected.length)rows.push('No matching document. No inferred answer.');
    else rows.push('\nOpen the containing document with native read for authoritative metadata, rationale, sources and cross-references; optional summary follows fragments.');
    if(fs.readFileSync(manifestFile,'utf8')!==before)return 'Snapshot changed during lookup; retry the native read. No inferred answer.\n';
    return rows.join('\n')+'\n';
  }catch{return 'Projection unavailable or read incomplete. No inferred answer; do not bypass it.\n';}
}
if(process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  const {parse}=await import('/opt/uas/pi/node_modules/yaml/dist/index.js');
  try {process.stdout.write(scan('/project/reference',process.argv.slice(2),{parse: text=>parse(text,{maxAliasCount:0})}));}
  catch {process.stderr.write('Use one or more literal query terms; no path options.\n');process.exitCode=2;}
}
