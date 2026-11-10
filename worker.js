const CORS={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Authorization,Content-Type,X-Filename','Access-Control-Allow-Methods':'GET,POST,PATCH,DELETE,OPTIONS','Access-Control-Expose-Headers':'Content-Range,Accept-Ranges,Content-Length'};
const J=(d,s=200)=>new Response(JSON.stringify(d),{status:s,headers:{...CORS,'Content-Type':'application/json'}});
class E extends Error{constructor(s,m){super(m);this.s=s}}
const enc=new TextEncoder(),dec=new TextDecoder();
const b64u=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const unb64u=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const unhex=h=>new Uint8Array(h.match(/../g).map(x=>parseInt(x,16)));
const q=(env,sql,...b)=>env.DB.prepare(sql).bind(...b);
const uid=()=>crypto.randomUUID();
async function hashPw(pw,saltHex){
const k=await crypto.subtle.importKey('raw',enc.encode(pw),'PBKDF2',false,['deriveBits']);
return hex(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:unhex(saltHex),iterations:100000},k,256));
}
const hkey=env=>crypto.subtle.importKey('raw',enc.encode(env.JWT_SECRET),{name:'HMAC',hash:'SHA-256'},false,['sign','verify']);
async function mint(env,id){
const p=b64u(enc.encode(JSON.stringify({u:id,e:Date.now()+30*864e5})));
return p+'.'+b64u(await crypto.subtle.sign('HMAC',await hkey(env),enc.encode(p)));
}
async function who(env,req){
const [p,s]=(req.headers.get('Authorization')||'').slice(7).split('.');
if(!p||!s)return null;
try{
if(!await crypto.subtle.verify('HMAC',await hkey(env),unb64u(s),enc.encode(p)))return null;
const d=JSON.parse(dec.decode(unb64u(p)));
if(d.e<Date.now())return null;
return await q(env,'select id,email,username,bio,is_admin,avatar_key,tos_at,email_alerts from users where id=?',d.u).first();
}catch(e){return null}
}
const SEL=`select a.*,u.username owner_name,u.avatar_key owner_avatar_key,
(select version_name from versions v where v.app_id=a.id and v.status='approved' order by version_code desc limit 1) version_name,
(select version_code from versions v where v.app_id=a.id and v.status='approved' order by version_code desc limit 1) version_code,
(select size from versions v where v.app_id=a.id and v.status='approved' order by version_code desc limit 1) size,
(select round(avg(rating),1) from reviews r where r.app_id=a.id) rating,
(select count(*) from reviews r where r.app_id=a.id) rating_count
from apps a join users u on u.id=a.owner_id`;
const shape=(a,base)=>({...a,owner_avatar:a.owner_avatar_key?base+'/files/'+a.owner_avatar_key:null,tags:JSON.parse(a.tags||'[]'),shot_keys:JSON.parse(a.shots||'[]'),shots:JSON.parse(a.shots||'[]').map(k=>base+'/files/'+k),icon_url:a.icon_key?base+'/files/'+a.icon_key:null,is_exclusive:!!a.is_exclusive});
const mine=(key,id)=>!key||String(key).startsWith(id+'/');
const clip=(s,n)=>String(s==null?'':s).trim().slice(0,n);
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const pub=(u,base)=>({id:u.id,email:u.email,username:u.username,bio:u.bio||'',is_admin:u.is_admin,avatar_url:u.avatar_key?base+'/files/'+u.avatar_key:null,tos:!!u.tos_at,email_alerts:u.email_alerts===0?0:1});
const fsize=b=>b>=1048576?(b/1048576).toFixed(1)+' MB':Math.max(1,Math.round(b/1024))+' KB';
async function delFile(env,key){
const f=await q(env,'select asset_id from files where key=?',key).first();
if(f){try{await gh(env,'DELETE','/releases/assets/'+f.asset_id)}catch(e){}await q(env,'delete from files where key=?',key).run()}
}
async function tell(env,userId,appId,vid,title,body){
await q(env,'insert into notifications(id,user_id,app_id,version_id,title,body,created_at) values(?,?,?,?,?,?,?)',uid(),userId,appId,vid||null,title,body,Date.now()).run();
}
async function mail(env,to,subject,html){
if(!env.BREVO_API_KEY||!env.MAIL_FROM)return;
try{await fetch('https://api.brevo.com/v3/smtp/email',{method:'POST',headers:{'api-key':env.BREVO_API_KEY,'Content-Type':'application/json',Accept:'application/json'},body:JSON.stringify({sender:{name:env.MAIL_NAME||'HEXSTORE',email:env.MAIL_FROM},to:[{email:to}],subject,htmlContent:html})})}catch(e){}
}
async function alertAdmins(env,ctx,a,ver,who){
const title=(a.status==='published'?'Update awaiting review: ':'New app awaiting review: ')+a.name;
const body='v'+ver.version_name+' from '+who+'. Open Profile, then Moderation.';
await q(env,"insert into notifications(id,user_id,app_id,version_id,title,body,created_at) select lower(hex(randomblob(16))),u.id,?1,?2,?3,?4,?5 from users u where u.is_admin=1",a.id,ver.id,title,body,Date.now()).run();
const rs=(await q(env,'select email from users where is_admin=1 and email_alerts=1').all()).results;
const html='<div style="font-family:system-ui,Arial,sans-serif;max-width:480px;margin:auto;background:#111216;color:#fff;border-radius:16px;padding:24px"><h2 style="margin:0 0 8px">'+esc(title)+'</h2><p>'+esc(body)+'</p></div>';
const job=Promise.all(rs.map(r=>mail(env,r.email,title,html)));
if(ctx&&ctx.waitUntil)ctx.waitUntil(job);else await job;
}
async function announce(env,ctx,base,a,ver){
const prior=(await q(env,"select count(*) n from versions where app_id=? and status='approved' and id<>?",a.id,ver.id).first()).n;
if(a.status!=='published'||!prior)return;
const title=a.name+' updated to v'+ver.version_name,body=ver.changelog||'A new version is available.';
await q(env,"insert into notifications(id,user_id,app_id,version_id,title,body,created_at) select lower(hex(randomblob(16))),f.user_id,?1,?2,?3,?4,?5 from follows f where f.app_id=?1 and f.user_id<>?6",a.id,ver.id,title,body,Date.now(),a.owner_id).run();
const rs=(await q(env,'select u.email from follows f join users u on u.id=f.user_id where f.app_id=? and u.email_alerts=1 and f.user_id<>? limit 100',a.id,a.owner_id).all()).results;
const link=base+'/a/'+a.id;
const html='<div style="font-family:system-ui,Arial,sans-serif;max-width:480px;margin:auto;background:#111216;color:#fff;border-radius:16px;padding:24px"><h2 style="margin:0 0 6px">'+esc(a.name)+'</h2><p style="color:#9a9aa4;margin:0 0 16px">Version '+esc(ver.version_name)+' is available</p><p style="white-space:pre-wrap">'+esc(body)+'</p><p><a href="'+link+'" style="display:inline-block;background:#e4e4e7;color:#111;padding:12px 20px;border-radius:10px;text-decoration:none;font-weight:600">Open &amp; download</a></p><p style="color:#6b6b75;font-size:12px">You follow this app on HEXSTORE. Turn off email alerts in Profile, then Edit profile.</p></div>';
const job=Promise.all(rs.map(r=>mail(env,r.email,title,html)));
if(ctx&&ctx.waitUntil)ctx.waitUntil(job);else await job;
}
export default{
async fetch(req,env,ctx){
if(req.method==='OPTIONS')return new Response(null,{status:204,headers:CORS});
const url=new URL(req.url),path=url.pathname;
try{
const miss=['DB','JWT_SECRET','GITHUB_TOKEN','GITHUB_OWNER','GITHUB_REPO'].filter(k=>!env[k]);
if(miss.length)throw new E(500,'Setup incomplete. Missing: '+miss.join(', ')+'. Add exactly these names to the Worker, then press Deploy.');
if(path.startsWith('/files/'))return await file(req,env,decodeURIComponent(path.slice(7)));
if(path.startsWith('/a/'))return await sharePage(env,url,decodeURIComponent(path.slice(3)));
if(!path.startsWith('/api/'))return J({name:'HEXSTORE API',ok:true});
return await api(req,env,url,path,ctx);
}catch(e){return J({error:e.s?e.message:'Server error: '+(e.message||'')},e.s||500)}
}
};
const GH=env=>({Authorization:'Bearer '+env.GITHUB_TOKEN,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'hexstore'});
const gh=(env,method,path,body)=>fetch('https://api.github.com/repos/'+env.GITHUB_OWNER+'/'+env.GITHUB_REPO+path,{method,headers:GH(env),body:body?JSON.stringify(body):undefined});
async function release(env){
const tag='files-'+new Date().toISOString().slice(0,7);
let r=await gh(env,'GET','/releases/tags/'+tag);
if(r.status===404){
r=await gh(env,'POST','/releases',{tag_name:tag,name:'Files '+tag,body:'HEXSTORE uploads',draft:false,prerelease:false,make_latest:'false'});
if(r.status===422)r=await gh(env,'GET','/releases/tags/'+tag);
}
const j=await r.json().catch(()=>({}));
if(!r.ok)throw new E(502,'GitHub storage error: '+(j.message||r.status)+'. Check GITHUB_TOKEN, GITHUB_OWNER and GITHUB_REPO.');
return {id:j.id,tag};
}
async function ghUpload(env,relId,name,type,stream,len){
let body=stream;
if(typeof FixedLengthStream!=='undefined'){const f=new FixedLengthStream(len);stream.pipeTo(f.writable);body=f.readable}
const r=await fetch('https://uploads.github.com/repos/'+env.GITHUB_OWNER+'/'+env.GITHUB_REPO+'/releases/'+relId+'/assets?name='+encodeURIComponent(name),{method:'POST',headers:{...GH(env),'Content-Type':type},body,duplex:'half'});
const j=await r.json().catch(()=>({}));
if(!r.ok)throw new E(502,'GitHub upload failed: '+(j.message||r.status));
return j;
}
async function file(req,env,key){
const f=await q(env,'select tag,asset from files where key=?',key).first();
if(!f)throw new E(404,'File not found');
return new Response(null,{status:302,headers:{...CORS,'Location':'https://github.com/'+env.GITHUB_OWNER+'/'+env.GITHUB_REPO+'/releases/download/'+f.tag+'/'+encodeURIComponent(f.asset),'Cache-Control':'public, max-age=3600'}});
}
async function api(req,env,url,path,ctx){
const m=req.method,base=url.origin,me=await who(env,req),now=Date.now();
const body=(m==='POST'||m==='PATCH'||m==='PUT')&&path!=='/api/upload'?await req.json().catch(()=>({})):{};
const need=()=>{if(!me)throw new E(401,'Please sign in first.')};
let r;
if(path==='/api/register'&&m==='POST'){
const email=clip(body.email,120).toLowerCase(),pw=String(body.password||'');
if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))throw new E(400,'Enter a valid email.');
if(pw.length<6)throw new E(400,'Password must be at least 6 characters.');
if(await q(env,'select 1 x from users where email=?',email).first())throw new E(409,'That email already has an account. Sign in instead.');
const first=(await q(env,'select count(*) n from users').first()).n===0;
const id=uid(),salt=hex(crypto.getRandomValues(new Uint8Array(16)));
const name=clip(body.username,30)||email.split('@')[0].slice(0,30);
await q(env,'insert into users(id,email,pass_hash,username,is_admin,created_at) values(?,?,?,?,?,?)',id,email,salt+':'+await hashPw(pw,salt),name,first?1:0,now).run();
return J({token:await mint(env,id),user:pub({id,email,username:name,bio:'',is_admin:first?1:0,email_alerts:1},base)});
}
if(path==='/api/login'&&m==='POST'){
const email=clip(body.email,120).toLowerCase();
const u=await q(env,'select * from users where email=?',email).first();
if(!u)throw new E(401,'Wrong email or password.');
const [salt,h]=u.pass_hash.split(':');
if(await hashPw(String(body.password||''),salt)!==h)throw new E(401,'Wrong email or password.');
return J({token:await mint(env,u.id),user:pub(u,base)});
}
if(path==='/api/me'&&m==='GET'){
need();
const s=await q(env,'select (select count(*) from apps where owner_id=?1) apps,(select coalesce(sum(downloads),0) from apps where owner_id=?1) downloads,(select count(*) from favorites where user_id=?1) favorites,(select count(*) from notifications where user_id=?1 and is_read=0) unread',me.id).first();
const c=await q(env,'select created_at from users where id=?',me.id).first();
return J({user:{...pub(me,base),created_at:c.created_at},stats:s});
}
if(path==='/api/me'&&m==='PATCH'){
need();const f={};
if(body.username!==undefined){const n=clip(body.username,30);if(n.length<2)throw new E(400,'Username needs at least 2 characters.');f.username=n}
if(body.bio!==undefined)f.bio=clip(body.bio,300);
if(body.email_alerts!==undefined)f.email_alerts=body.email_alerts?1:0;
if(body.avatar_key!==undefined){
const k=body.avatar_key||null;if(k&&!mine(k,me.id))throw new E(400,'Invalid photo.');
if(me.avatar_key&&me.avatar_key!==k)await delFile(env,me.avatar_key);
f.avatar_key=k;
}
const ks=Object.keys(f);
if(ks.length)await q(env,'update users set '+ks.map(k=>k+'=?').join(',')+' where id=?',...ks.map(k=>f[k]),me.id).run();
return J({ok:true});
}
if(path==='/api/me/terms'&&m==='POST'){
need();await q(env,'update users set tos_at=? where id=?',now,me.id).run();return J({ok:true});
}
if((r=path.match(/^\/api\/users\/([\w-]+)$/))&&m==='GET'){
const u=await q(env,'select id,username,bio,avatar_key,created_at from users where id=?',r[1]).first();
if(!u)throw new E(404,'User not found');
const s=await q(env,"select count(*) apps,coalesce(sum(downloads),0) downloads from apps where owner_id=? and status='published'",r[1]).first();
return J({user:{id:u.id,username:u.username,bio:u.bio,created_at:u.created_at,avatar_url:u.avatar_key?base+'/files/'+u.avatar_key:null},stats:s});
}
if(path==='/api/upload'&&m==='POST'){
need();
const kind=url.searchParams.get('kind'),len=+req.headers.get('Content-Length');
const name=clip(decodeURIComponent(req.headers.get('X-Filename')||'file'),120);
if(!len)throw new E(411,'Missing file size.');
let ext,type;
if(kind==='apk'){
if(!me.tos_at)throw new E(403,'Please accept the Terms of Service first.');
if(!/\.apk$/i.test(name))throw new E(400,'Choose an .apk file.');
if(len>100*1024*1024)throw new E(413,'APK is over the 100 MB limit.');
ext='.apk';type='application/vnd.android.package-archive';
}else if(kind==='image'){
type=req.headers.get('Content-Type')||'';
if(!/^image\/(png|jpeg|webp|gif)$/.test(type))throw new E(400,'Use a PNG or JPG image.');
if(len>5*1024*1024)throw new E(413,'Image is over the 5 MB limit.');
ext={'image/png':'.png','image/jpeg':'.jpg','image/webp':'.webp','image/gif':'.gif'}[type];
}else throw new E(400,'Unknown upload kind.');
const key=me.id+'/'+uid()+ext;
const rel=await release(env);
const asset=uid().slice(0,8)+'-'+(name.replace(/\.[^.]+$/,'').replace(/[^a-zA-Z0-9]+/g,'-').replace(/^-|-$/g,'').slice(0,40)||'file')+ext;
const up=await ghUpload(env,rel.id,asset,type,req.body,len);
await q(env,'insert into files(key,owner_id,tag,asset,asset_id,orig_name,size,created_at) values(?,?,?,?,?,?,?,?)',key,me.id,rel.tag,asset,up.id,name,len,now).run();
return J({key,size:len,url:base+'/files/'+key});
}
if(path==='/api/apps'&&m==='GET'){
const p=url.searchParams,text=clip(p.get('q'),60);let where,b=[];
if(p.get('mine')){need();where='a.owner_id=?';b=[me.id]}
else if(p.get('status')==='pending'){need();if(!me.is_admin)throw new E(403,'Admins only.');where="a.status='pending'"}
else where="a.status='published'";
if(text){where+=' and (a.name like ? or a.category like ?)';b.push('%'+text+'%','%'+text+'%')}
const rows=(await q(env,SEL+' where '+where+' order by a.updated_at desc limit 100',...b).all()).results;
return J({apps:rows.map(a=>shape(a,base))});
}
if(path==='/api/apps'&&m==='POST'){
need();
if(!me.tos_at)throw new E(403,'Please accept the Terms of Service first.');
const name=clip(body.name,80),cat=clip(body.category,40),desc=clip(body.description,4000),sum=clip(body.summary,50);
const draft=body.status==='draft';
if(!name)throw new E(400,'Enter an app name.');
if(!cat)throw new E(400,'Choose a category.');
if(!draft&&desc.length<100)throw new E(400,'Description needs at least 100 characters.');
if(!draft&&!['original','mod'].includes(body.origin))throw new E(400,'Choose Original or Mod.');
if(!mine(body.icon_key,me.id))throw new E(400,'Invalid icon.');
const shots=(Array.isArray(body.shots)?body.shots:[]).filter(k=>mine(k,me.id)).slice(0,8);
const id=uid(),status=draft?'draft':(me.is_admin?'published':'pending');
await q(env,'insert into apps(id,owner_id,name,category,description,summary,origin,source_url,is_exclusive,tags,icon_key,shots,status,created_at,updated_at) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
id,me.id,name,cat,desc,sum,body.origin||null,clip(body.source_url,200)||null,body.is_exclusive?1:0,JSON.stringify((Array.isArray(body.tags)?body.tags:[]).map(t=>clip(t,24)).slice(0,8)),body.icon_key||null,JSON.stringify(shots),status,now,now).run();
return J({id,status});
}
if((r=path.match(/^\/api\/apps\/([\w-]+)$/))){
const id=r[1];
const a=await q(env,SEL+' where a.id=?',id).first();
if(!a)throw new E(404,'App not found');
const owner=!!me&&me.id===a.owner_id,admin=!!me&&!!me.is_admin;
if(m==='GET'){
if(!(a.status==='published'||owner||admin))throw new E(404,'App not found');
const vs=(await q(env,(owner||admin)?'select * from versions where app_id=? order by version_code desc':"select * from versions where app_id=? and status='approved' order by version_code desc",id).all()).results.map(v=>({...v,apk_url:base+'/files/'+v.apk_key}));
const rv=(await q(env,'select r.rating,r.comment,r.created_at,u.username,u.avatar_key from reviews r join users u on u.id=r.user_id where r.app_id=? order by r.created_at desc limit 30',id).all()).results.map(x=>({rating:x.rating,comment:x.comment,created_at:x.created_at,username:x.username,avatar_url:x.avatar_key?base+'/files/'+x.avatar_key:null}));
const dist=(await q(env,'select rating,count(*) n from reviews where app_id=? group by rating',id).all()).results;
let following=false,favorited=false,my_review=null;
if(me){
following=!!await q(env,'select 1 x from follows where user_id=? and app_id=?',me.id,id).first();
favorited=!!await q(env,'select 1 x from favorites where user_id=? and app_id=?',me.id,id).first();
my_review=await q(env,'select rating,comment from reviews where user_id=? and app_id=?',me.id,id).first();
}
return J({app:shape(a,base),versions:vs,reviews:rv,dist,following,favorited,my_review,is_owner:owner});
}
if(!(owner||admin))throw new E(403,'Only the developer can change this app.');
if(m==='PATCH'){
const f={};
if(body.name!==undefined){f.name=clip(body.name,80);if(!f.name)throw new E(400,'Enter an app name.')}
if(body.category!==undefined)f.category=clip(body.category,40);
if(body.description!==undefined)f.description=clip(body.description,4000);
if(body.summary!==undefined)f.summary=clip(body.summary,50);
if(body.origin!==undefined&&['original','mod'].includes(body.origin))f.origin=body.origin;
if(body.source_url!==undefined)f.source_url=clip(body.source_url,200)||null;
if(body.is_exclusive!==undefined)f.is_exclusive=body.is_exclusive?1:0;
if(Array.isArray(body.tags))f.tags=JSON.stringify(body.tags.map(t=>clip(t,24)).slice(0,8));
if(body.icon_key!==undefined){if(!mine(body.icon_key,a.owner_id))throw new E(400,'Invalid icon.');if(a.icon_key&&a.icon_key!==body.icon_key)await delFile(env,a.icon_key);f.icon_key=body.icon_key}
if(Array.isArray(body.shots)){const ns=body.shots.filter(k=>mine(k,a.owner_id)).slice(0,8);for(const k of JSON.parse(a.shots||'[]'))if(!ns.includes(k))await delFile(env,k);f.shots=JSON.stringify(ns)}
if(body.status!==undefined){
if(admin&&['draft','pending','published','rejected'].includes(body.status))f.status=body.status;
else if(owner&&['draft','pending'].includes(body.status)&&a.status!=='published')f.status=(body.status==='pending'&&admin)?'published':body.status;
}
const keys=Object.keys(f);
if(keys.length){await q(env,'update apps set '+keys.map(k=>k+'=?').join(',')+',updated_at=? where id=?',...keys.map(k=>f[k]),now,id).run()}
if(f.status==='published')await q(env,"update versions set status='approved' where app_id=? and status='pending'",id).run();
return J({ok:true});
}
if(m==='DELETE'){
const vs=(await q(env,'select apk_key from versions where app_id=?',id).all()).results;
const keys=[...vs.map(v=>v.apk_key),a.icon_key,...JSON.parse(a.shots||'[]')].filter(Boolean);
await q(env,'delete from apps where id=?',id).run();
for(const k of keys)await delFile(env,k);
return J({ok:true});
}
}
if((r=path.match(/^\/api\/apps\/([\w-]+)\/versions$/))&&m==='POST'){
need();
if(!me.tos_at)throw new E(403,'Please accept the Terms of Service first.');
const a=await q(env,'select * from apps where id=?',r[1]).first();
if(!a||!(a.owner_id===me.id||me.is_admin))throw new E(403,'Only the developer can upload versions.');
const vn=clip(body.version_name,30);
if(!vn)throw new E(400,'Enter a version name, for example 1.1');
if(!body.apk_key||!mine(body.apk_key,a.owner_id)||!/\.apk$/.test(body.apk_key))throw new E(400,'Upload the APK first.');
const code=(await q(env,'select coalesce(max(version_code),0)+1 c from versions where app_id=?',a.id).first()).c;
const vid=uid(),log=clip(body.changelog,2000),st=me.is_admin?'approved':'pending';
await q(env,'insert into versions(id,app_id,version_name,version_code,changelog,apk_key,size,status,created_at) values(?,?,?,?,?,?,?,?,?)',vid,a.id,vn,code,log,body.apk_key,+body.size||0,st,now).run();
await q(env,'update apps set updated_at=? where id=?',now,a.id).run();
if(st==='approved')await announce(env,ctx,base,a,{id:vid,version_name:vn,changelog:log});
else await alertAdmins(env,ctx,a,{id:vid,version_name:vn},me.username);
return J({id:vid,version_code:code,status:st});
}
if((r=path.match(/^\/api\/versions\/([\w-]+)\/download$/))&&m==='POST'){
const v=await q(env,'select app_id from versions where id=?',r[1]).first();
if(v){await q(env,'update versions set downloads=downloads+1 where id=?',r[1]).run();await q(env,'update apps set downloads=downloads+1 where id=?',v.app_id).run()}
return J({ok:true});
}
if((r=path.match(/^\/api\/apps\/([\w-]+)\/(follow|favorite)$/))&&m==='POST'){
need();
const t=r[2]==='follow'?'follows':'favorites';
if(body.on)await q(env,'insert or ignore into '+t+'(user_id,app_id) values(?,?)',me.id,r[1]).run();
else await q(env,'delete from '+t+' where user_id=? and app_id=?',me.id,r[1]).run();
return J({ok:true});
}
if((r=path.match(/^\/api\/apps\/([\w-]+)\/reviews$/))&&m==='POST'){
need();
const rating=Math.round(+body.rating);
if(!(rating>=1&&rating<=5))throw new E(400,'Tap a star to rate.');
await q(env,'insert into reviews(id,app_id,user_id,rating,comment,created_at) values(?,?,?,?,?,?) on conflict(app_id,user_id) do update set rating=excluded.rating,comment=excluded.comment,created_at=excluded.created_at',uid(),r[1],me.id,rating,clip(body.comment,1000),now).run();
return J({ok:true});
}
if(path==='/api/favorites'&&m==='GET'){
need();
const rows=(await q(env,SEL+" where a.status='published' and a.id in (select app_id from favorites where user_id=?) order by a.updated_at desc",me.id).all()).results;
return J({apps:rows.map(a=>shape(a,base))});
}
if(path==='/api/admin/queue'&&m==='GET'){
need();if(!me.is_admin)throw new E(403,'Admins only.');
const items=[];
const pa=(await q(env,SEL+" where a.status='pending' order by a.updated_at asc").all()).results;
for(const a of pa){
const v=await q(env,"select * from versions where app_id=? and status='pending' order by version_code desc limit 1",a.id).first();
const o=await q(env,'select username,email from users where id=?',a.owner_id).first();
items.push({type:'app',app:shape(a,base),version:v?{...v,apk_url:base+'/files/'+v.apk_key}:null,uploader:o});
}
const pv=(await q(env,"select v.* from versions v join apps a on a.id=v.app_id where v.status='pending' and a.status='published' order by v.created_at asc").all()).results;
for(const v of pv){
const a=await q(env,SEL+' where a.id=?',v.app_id).first();
const o=await q(env,'select username,email from users where id=?',a.owner_id).first();
items.push({type:'version',app:shape(a,base),version:{...v,apk_url:base+'/files/'+v.apk_key},uploader:o});
}
return J({items});
}
if(path==='/api/admin/review'&&m==='POST'){
need();if(!me.is_admin)throw new E(403,'Admins only.');
const ok=body.decision==='approve',reason=clip(body.reason,500);
if(!ok&&body.decision!=='reject')throw new E(400,'Choose approve or reject.');
if(!ok&&!reason)throw new E(400,'Write a reason so the developer knows what to fix.');
if(body.type==='app'){
const a=await q(env,'select * from apps where id=?',body.id).first();if(!a)throw new E(404,'App not found');
if(ok){
await q(env,"update apps set status='published',reject_reason=null,updated_at=? where id=?",now,a.id).run();
const lv=await q(env,"select id from versions where app_id=? and status='pending' order by version_code desc limit 1",a.id).first();
if(lv){
await q(env,"update versions set status='approved' where id=?",lv.id).run();
await q(env,"update versions set status='rejected',reject_reason='Replaced by a newer version.' where app_id=? and status='pending'",a.id).run();
}
await tell(env,a.owner_id,a.id,null,a.name+' is now live','Your app was approved and is visible in the store.');
}else{
await q(env,"update apps set status='rejected',reject_reason=?,updated_at=? where id=?",reason,now,a.id).run();
await tell(env,a.owner_id,a.id,null,a.name+' was not approved','Reason: '+reason);
}
}else if(body.type==='version'){
const v=await q(env,'select * from versions where id=?',body.id).first();if(!v)throw new E(404,'Version not found');
const a=await q(env,'select * from apps where id=?',v.app_id).first();
if(ok){
await q(env,"update versions set status='approved',reject_reason=null where id=?",v.id).run();
await q(env,'update apps set updated_at=? where id=?',now,a.id).run();
await tell(env,a.owner_id,a.id,v.id,a.name+' v'+v.version_name+' is now live','Your update was approved. Followers have been notified.');
await announce(env,ctx,base,a,{id:v.id,version_name:v.version_name,changelog:v.changelog});
}else{
await q(env,"update versions set status='rejected',reject_reason=? where id=?",reason,v.id).run();
await tell(env,a.owner_id,a.id,v.id,a.name+' v'+v.version_name+' was not approved','Reason: '+reason);
}
}else throw new E(400,'Unknown item.');
return J({ok:true});
}
if(path==='/api/notifications'&&m==='GET'){
need();
const rows=(await q(env,'select * from notifications where user_id=? order by created_at desc limit 50',me.id).all()).results;
return J({notifications:rows,unread:rows.filter(n=>!n.is_read).length});
}
if(path==='/api/notifications/read'&&m==='POST'){
need();
await q(env,'update notifications set is_read=1 where user_id=?',me.id).run();
return J({ok:true});
}
throw new E(404,'Not found');
}
async function sharePage(env,url,id){
const a=await q(env,SEL+' where a.id=?',id).first();
if(!a||a.status!=='published')return new Response('App not found',{status:404,headers:{'Content-Type':'text/plain'}});
const base=url.origin;
const v=await q(env,"select * from versions where app_id=? and status='approved' order by version_code desc limit 1",id).first();
const icon=a.icon_key?base+'/files/'+a.icon_key:'';
const desc=esc(a.summary||String(a.description).slice(0,160));
const html='<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+esc(a.name)+' — HEXSTORE</title><meta name="description" content="'+desc+'"><meta property="og:title" content="'+esc(a.name)+' — free APK on HEXSTORE"><meta property="og:description" content="'+desc+'">'+(icon?'<meta property="og:image" content="'+esc(icon)+'">':'')+'<meta name="theme-color" content="#0a0a0c"><style>*{box-sizing:border-box}body{margin:0;background:#0a0a0c;color:#f4f4f5;font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}main{max-width:560px;margin:auto;padding:28px 18px 60px}.top{display:flex;align-items:center;gap:10px;color:#9a9aa4;font-weight:700;letter-spacing:.08em;font-size:13px;margin-bottom:26px}.top i{width:30px;height:30px;border-radius:9px;background:linear-gradient(135deg,#43c25c,#27913f);display:inline-block}.card{background:#17171b;border:1px solid #2b2b31;border-radius:24px;padding:24px}.ic{width:112px;height:112px;border-radius:26px;object-fit:cover;background:#222227;display:block}h1{font-size:30px;margin:18px 0 4px;letter-spacing:-.02em}.mu{color:#9a9aa4}.btn{display:block;text-align:center;background:#e4e4e7;color:#111;text-decoration:none;font-weight:700;border-radius:14px;padding:16px;margin-top:20px}.st{display:grid;grid-template-columns:repeat(3,1fr);border-top:1px solid #2b2b31;margin:22px -24px 0;padding-top:16px;text-align:center;font-size:12px;color:#9a9aa4;text-transform:uppercase}.st b{display:block;font-size:20px;color:#f4f4f5;text-transform:none}h2{font-size:20px;margin:28px 0 8px}p{margin:0 0 10px;white-space:pre-wrap}</style></head><body><main><div class="top"><i></i>HEXSTORE</div><div class="card">'+(icon?'<img class="ic" src="'+esc(icon)+'" alt="">':'<div class="ic"></div>')+'<h1>'+esc(a.name)+'</h1>'+(a.summary?'<p class="mu">'+esc(a.summary)+'</p>':'')+'<p class="mu">by '+esc(a.owner_name)+' · '+esc(a.category)+'</p>'+(v?'<a class="btn" href="'+base+'/files/'+esc(v.apk_key)+'">Download APK</a>':'<div class="btn" style="opacity:.5">No download available</div>')+'<div class="st"><div><b>'+(a.rating||'–')+'</b>Rating</div><div><b>'+a.downloads+'</b>Downloads</div><div><b>'+(v?fsize(v.size):'–')+'</b>Size</div></div></div>'+(v?'<h2>What’s new in v'+esc(v.version_name)+'</h2><p>'+esc(v.changelog||'Initial release')+'</p>':'')+'<h2>About this app</h2><p>'+esc(a.description)+'</p></main></body></html>';
return new Response(html,{headers:{'Content-Type':'text/html;charset=utf-8','Cache-Control':'public, max-age=300'}});
}
