const CORS={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Authorization,Content-Type,X-Filename,Range','Access-Control-Allow-Methods':'GET,POST,PATCH,DELETE,OPTIONS','Access-Control-Expose-Headers':'Content-Range,Accept-Ranges,Content-Length'};
const J=(d,s=200)=>new Response(JSON.stringify(d),{status:s,headers:{...CORS,'Content-Type':'application/json'}});
class E extends Error{constructor(s,m){super(m);this.s=s}}
const enc=new TextEncoder(),dec=new TextDecoder();
const b64u=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const unb64u=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const unhex=h=>new Uint8Array(h.match(/../g).map(x=>parseInt(x,16)));
const q=(env,sql,...b)=>env.DB.prepare(sql).bind(...b);
const uid=()=>crypto.randomUUID();
const sd=s=>{try{return decodeURIComponent(s)}catch(e){return ''}};

const PACKAGE_NAME='com.hexstore.app';

// ---- Rate limits (login, register, uploads) ----
const ipOf=req=>req.headers.get('CF-Connecting-IP')||'unknown';
async function limited(env,key,max,win,now){
  const r=await q(env,'select fails,window_start from login_attempts where k=?',key).first();
  return Boolean(r&&now-r.window_start<win&&r.fails>=max);
}
async function bump(env,key,win,now){
  await q(env,'insert into login_attempts(k,fails,window_start) values(?1,1,?2) on conflict(k) do update set fails=case when ?2-window_start>=?3 then 1 else fails+1 end,window_start=case when ?2-window_start>=?3 then ?2 else window_start end',key,now,win).run();
}
async function clearKey(env,key){await q(env,'delete from login_attempts where k=?',key).run()}
const TOO_MANY='Too many tries. Please wait a few minutes and try again.';


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
    return await q(env,'select id,email,username,bio,is_admin,avatar_key,tos_at,email_alerts,coins,welcome_at,cash_enabled,payout_details from users where id=?',d.u).first();
  }catch(e){return null}
}

const SEL=`select a.*,u.username owner_name,u.avatar_key owner_avatar_key,u.is_admin owner_is_admin,
(select count(*) from dev_follows where dev_id=u.id) owner_followers,
(select coalesce(sum(downloads),0) from apps where owner_id=u.id and status='published') owner_downloads,
(select version_name from versions v where v.app_id=a.id and v.status='approved' order by version_code desc limit 1) version_name,
(select version_code from versions v where v.app_id=a.id and v.status='approved' order by version_code desc limit 1) version_code,
(select size from versions v where v.app_id=a.id and v.status='approved' order by version_code desc limit 1) size,
(select round(avg(rating),1) from reviews r where r.app_id=a.id) rating,
(select count(*) from reviews r where r.app_id=a.id) rating_count
from apps a join users u on u.id=a.owner_id`;

const shape=(a,base)=>({
  ...a,
  owner_avatar:a.owner_avatar_key?base+'/files/'+a.owner_avatar_key:null,
  tags:jp(a.tags,[]),
  shot_keys:jp(a.shots,[]),
  shots:jp(a.shots,[]).map(k=>base+'/files/'+k),
  icon_url:a.icon_key?base+'/files/'+a.icon_key:null,
  is_exclusive:Boolean(a.is_exclusive),
  owner_is_admin:Boolean(a.owner_is_admin),
  owner_followers:+(a.owner_followers||0)+(a.owner_is_admin?256789:0),
  owner_downloads:+(a.owner_downloads||0),
  owner_is_prime:Boolean(a.owner_is_admin||(a.owner_downloads>=500))
});
const lite=(a,base)=>{const x=shape(a,base);x.description=String(a.description||'').slice(0,160);x.shots=[];x.shot_keys=[];return x};
const mine=(key,id)=>!key||String(key).startsWith(id+'/');
const clip=(s,n)=>String(s==null?'':s).trim().slice(0,n);
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const pub=(u,base)=>({id:u.id,email:u.email,username:u.username,bio:u.bio||'',is_admin:u.is_admin,avatar_url:u.avatar_key?base+'/files/'+u.avatar_key:null,tos:Boolean(u.tos_at),email_alerts:u.email_alerts===0?0:1,coins:+u.coins||0,cash_enabled:Boolean(u.cash_enabled)||Boolean(u.is_admin&&u.payout_details)});

async function delFile(env,key){
  const f=await q(env,'select asset_id from files where key=?',key).first();
  if(f){try{await gh(env,'DELETE','/releases/assets/'+f.asset_id)}catch(e){}await q(env,'delete from files where key=?',key).run()}
}
async function retireOld(env,appId){
  try{
    const latest=await q(env,"select version_code from versions where app_id=? and status='approved' and apk_key<>'' order by version_code desc limit 1",appId).first();
    if(!latest)return;
    const olds=(await q(env,"select id,apk_key from versions where app_id=? and status='approved' and apk_key<>'' and version_code<?",appId,latest.version_code).all()).results;
    for(const o of olds){await delFile(env,o.apk_key);await q(env,"update versions set apk_key='' where id=?",o.id).run()}
  }catch(e){}
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
  const html='<div style="font-family:system-ui,sans-serif;max-width:480px;margin:auto;background:#111216;color:#fff;border-radius:16px;padding:24px"><h2 style="margin:0 0 8px">'+esc(title)+'</h2><p>'+esc(body)+'</p></div>';
  const job=Promise.all(rs.map(r=>mail(env,r.email,title,html)));
  if(ctx&&ctx.waitUntil)ctx.waitUntil(job);else await job;
}
async function announce(env,ctx,base,a,ver){
  const prior=(await q(env,"select count(*) n from versions where app_id=? and status='approved' and id<>?",a.id,ver.id).first()).n;
  if(a.status!=='published'||!prior)return;
  const title=a.name+' updated to v'+ver.version_name,body=ver.changelog||'A new version is available.';
  await q(env,"insert into notifications(id,user_id,app_id,version_id,title,body,created_at) select lower(hex(randomblob(16))),f.user_id,?1,?2,?3,?4,?5 from (select user_id from follows where app_id=?1 union select user_id from installs where app_id=?1) f where f.user_id<>?6",a.id,ver.id,title,body,Date.now(),a.owner_id).run();
  const rs=(await q(env,'select u.email from (select user_id from follows where app_id=?1 union select user_id from installs where app_id=?1) f join users u on u.id=f.user_id where u.email_alerts=1 and f.user_id<>?2 limit 100',a.id,a.owner_id).all()).results;
  const link=base+'/a/'+a.id;
  const html='<div style="font-family:system-ui,sans-serif;max-width:480px;margin:auto;background:#111216;color:#fff;border-radius:16px;padding:24px"><h2 style="margin:0 0 6px">'+esc(a.name)+'</h2><p style="color:#9a9aa4;margin:0 0 16px">Version '+esc(ver.version_name)+' is available</p><p style="white-space:pre-wrap">'+esc(body)+'</p><p><a href="'+link+'" style="display:inline-block;background:#e4e4e7;color:#111;padding:12px 20px;border-radius:10px;text-decoration:none;font-weight:600">Open &amp; download</a></p></div>';
  const job=Promise.all(rs.map(r=>mail(env,r.email,title,html)));
  if(ctx&&ctx.waitUntil)ctx.waitUntil(job);else await job;
}


// ======================================================================
//  HEX COINS · PAID APPS · CASH KEYS · SHOP
// ======================================================================
const WELCOME_COINS=300,SCHEMA_V=1;
const CURRENCIES=['USD','EUR','GBP','NGN','GHS','KES','ZAR','INR','CAD','AUD','BRL','AED'];
const jp=(s,d)=>{try{const v=JSON.parse(s||'');return v==null?d:v}catch(e){return d}};
const HEXC=/^#[0-9a-fA-F]{6}$/;
const money=(c,cur)=>(c/100).toFixed(2)+' '+cur;
const orderRef=(appId,userId)=>'HX-'+(String(appId).replace(/-/g,'').slice(0,4)+String(userId).replace(/-/g,'').slice(0,4)).toUpperCase();

// Shop catalog. Prices are in Hex Coins. cfg = which options the owner can customise.
const SHOP=[
 {id:'intro',emoji:'🎬',name:'Welcome Intro',price:120,desc:'A cinematic full-screen welcome with your own message when someone opens your app page.',cfg:['c1','c2','text','speed'],max:60,def:{c1:'#43c25c',c2:'#1d9bf0',text:'Welcome!',speed:2}},
 {id:'nano',emoji:'💠',name:'Nano Border Light',price:150,desc:'A razor-thin light that races around your app card. Pick the colors, speed and thickness.',cfg:['c1','c2','speed','w'],def:{c1:'#43e5ff',c2:'#8a5cff',speed:2,w:2}},
 {id:'shotlight',emoji:'🖼️',name:'Image Border Light',price:100,desc:'A glowing light runs around every screenshot of your app.',cfg:['c1','c2','speed'],def:{c1:'#ffd84a',c2:'#ff5fa2',speed:2}},
 {id:'aurora',emoji:'🌌',name:'Aurora Banner',price:160,desc:'Soft northern-lights colors flowing behind your app header.',cfg:['c1','c2','speed'],def:{c1:'#2ee6a6',c2:'#7a5cff',speed:2}},
 {id:'iconglow',emoji:'✨',name:'Neon Icon Glow',price:80,desc:'Your app icon pulses with a neon halo.',cfg:['c1','speed'],def:{c1:'#43c25c',speed:2}},
 {id:'glass',emoji:'🧊',name:'Glass Card',price:140,desc:'Frosted-glass header card with a tinted, blurred backdrop.',cfg:['c1','c2'],def:{c1:'#5ec8ff',c2:'#c084fc'}},
 {id:'stars',emoji:'⭐',name:'Starfield',price:180,desc:'Twinkling stars drift across the whole page behind your app.',cfg:['c1','c2','speed'],def:{c1:'#ffffff',c2:'#8ab4ff',speed:2}},
 {id:'holo',emoji:'🌈',name:'Holo Shine',price:90,desc:'A holographic shimmer sweeps across your screenshots.',cfg:['c1','c2','speed'],def:{c1:'#ff6ad5',c2:'#4de1ff',speed:2}},
 {id:'crown',emoji:'👑',name:'Gold Crown Badge',price:200,desc:'A shining crown badge next to your app name. Set your own badge text.',cfg:['c1','c2','text'],max:14,def:{c1:'#ffd54a',c2:'#ff9d00',text:'FEATURED'}},
 {id:'accent',emoji:'🎨',name:'Custom Accent Color',price:60,desc:'Recolor buttons, progress bars and headings across your page.',cfg:['c1','c2'],def:{c1:'#ff5a7a',c2:'#ff9a44'}},
 {id:'btnshine',emoji:'⚡',name:'Shine Download Button',price:70,desc:'A glossy gradient download button with a moving light sweep.',cfg:['c1','c2','speed'],def:{c1:'#43c25c',c2:'#1db3a6',speed:2}},
 {id:'rainbow',emoji:'🔤',name:'Animated Title',price:110,desc:'Your app name flows with a moving two-color gradient.',cfg:['c1','c2','speed'],def:{c1:'#ff5fa2',c2:'#ffd84a',speed:2}},
 {id:'confetti',emoji:'🎉',name:'Confetti Burst',price:130,desc:'Confetti explodes when someone taps download or unlocks your app.',cfg:['c1','c2'],def:{c1:'#ff5fa2',c2:'#43e5ff'}}
];
const SHOP_BY=Object.fromEntries(SHOP.map(i=>[i.id,i]));
function cleanCfg(it,input,base){
  const out={...it.def,...(base||{})},inp=input&&typeof input==='object'?input:{};
  for(const k of it.cfg){
    const v=inp[k];if(v===undefined)continue;
    if(k==='c1'||k==='c2'){if(HEXC.test(String(v)))out[k]=String(v).toLowerCase()}
    else if(k==='speed'||k==='w'){const n=Math.round(+v);if(n>=1&&n<=3)out[k]=n}
    else if(k==='text')out.text=clip(v,it.max||40)||it.def.text;
  }
  const r={};for(const k of it.cfg)r[k]=out[k];return r;
}
const fxList=rows=>rows.filter(r=>SHOP_BY[r.item_id]).map(r=>({id:r.item_id,cfg:cleanCfg(SHOP_BY[r.item_id],jp(r.cfg,{}))}));

// ---- one-time, idempotent database upgrade (runs automatically) ----
let SCHEMA=null;
const ensureSchema=env=>SCHEMA||(SCHEMA=migrate(env).catch(e=>{SCHEMA=null;throw e}));
async function migrate(env){
  const run=s=>env.DB.prepare(s).run();
  await run('create table if not exists hx_meta(k text primary key,v text)');
  const cur=await env.DB.prepare("select v from hx_meta where k='schema'").first();
  if(cur&&+cur.v>=SCHEMA_V)return;
  const alters=[
    'alter table users add column coins integer not null default 0',
    'alter table users add column welcome_at integer',
    'alter table users add column cash_enabled integer not null default 0',
    "alter table users add column payout_details text not null default ''",
    "alter table apps add column price_mode text not null default 'free'",
    'alter table apps add column price integer not null default 0',
    "alter table apps add column currency text not null default 'USD'"
  ];
  for(const s of alters){try{await run(s)}catch(e){if(!/duplicate column/i.test(String(e.message)))throw e}}
  const st=[
    "create table if not exists coin_tx(id text primary key,user_id text not null references users(id) on delete cascade,amount integer not null,kind text not null,note text not null default '',ref text,created_at integer not null)",
    'create index if not exists idx_ctx_user on coin_tx(user_id,created_at)',
    "create table if not exists purchases(id text primary key,user_id text not null references users(id) on delete cascade,app_id text not null references apps(id) on delete cascade,method text not null,price integer not null default 0,currency text not null default '',created_at integer not null,unique(user_id,app_id))",
    'create index if not exists idx_pur_app on purchases(app_id)',
    "create table if not exists cash_orders(id text primary key,app_id text not null references apps(id) on delete cascade,buyer_id text not null,seller_id text not null,amount integer not null,currency text not null,ref text not null,note text not null default '',status text not null default 'pending',reason text,created_at integer not null,decided_at integer)",
    'create index if not exists idx_co_seller on cash_orders(seller_id,status,created_at)',
    'create index if not exists idx_co_buyer on cash_orders(buyer_id,app_id,created_at)',
    "create table if not exists cash_keys(code text primary key,note text not null default '',created_by text,created_at integer not null,used_by text,used_at integer)",
    "create table if not exists app_items(app_id text not null references apps(id) on delete cascade,item_id text not null,owner_id text not null,cfg text not null default '{}',enabled integer not null default 1,created_at integer not null,primary key(app_id,item_id))",
    // speed: indexes that were missing
    'create index if not exists idx_versions_apk on versions(apk_key)',
    'create index if not exists idx_versions_status on versions(app_id,status,version_code)',
    'create index if not exists idx_apps_owner on apps(owner_id,status)',
    'create index if not exists idx_follows_app on follows(app_id)',
    'create index if not exists idx_fav_app on favorites(app_id)',
    'create index if not exists idx_files_owner on files(owner_id,created_at)'
  ];
  await env.DB.batch(st.map(s=>env.DB.prepare(s)));
  await env.DB.prepare("insert into hx_meta(k,v) values('schema',?1) on conflict(k) do update set v=?1").bind(String(SCHEMA_V)).run();
}

// ---- coins ----
async function giveCoins(env,id,amt,kind,note,ref,now){
  await env.DB.batch([
    q(env,'update users set coins=coins+? where id=?',amt,id),
    q(env,'insert into coin_tx(id,user_id,amount,kind,note,ref,created_at) values(?,?,?,?,?,?,?)',uid(),id,amt,kind,note,ref||null,now)
  ]);
}
async function spendCoins(env,id,amt,kind,note,ref,now){
  const r=await q(env,'update users set coins=coins-?1 where id=?2 and coins>=?1',amt,id).run();
  if(!(r.meta&&r.meta.changes>0))return false;
  await q(env,'insert into coin_tx(id,user_id,amount,kind,note,ref,created_at) values(?,?,?,?,?,?,?)',uid(),id,-amt,kind,note,ref||null,now).run();
  return true;
}
async function welcome(env,id,now){
  const r=await q(env,'update users set coins=coins+?1,welcome_at=?2 where id=?3 and welcome_at is null',WELCOME_COINS,now,id).run();
  if(r.meta&&r.meta.changes>0){
    await q(env,"insert into coin_tx(id,user_id,amount,kind,note,created_at) values(?,?,?,'welcome','Welcome gift',?)",uid(),id,WELCOME_COINS,now).run();
    return true;
  }
  return false;
}
const balance=async(env,id)=>(await q(env,'select coins from users where id=?',id).first()).coins;

// ---- paid-app access ----
async function owns(env,me,a){
  if(!a.price_mode||a.price_mode==='free')return true;
  if(!me)return false;
  if(me.id===a.owner_id||me.is_admin)return true;
  return Boolean(await q(env,'select 1 x from purchases where user_id=? and app_id=?',me.id,a.id).first());
}
async function signTicket(env,key,ttl){
  const p=b64u(enc.encode(JSON.stringify({k:key,e:Date.now()+ttl})));
  return p+'.'+b64u(await crypto.subtle.sign('HMAC',await hkey(env),enc.encode('t:'+p)));
}
async function checkTicket(env,t,key){
  const [p,s]=String(t||'').split('.');if(!p||!s)return false;
  try{
    if(!await crypto.subtle.verify('HMAC',await hkey(env),unb64u(s),enc.encode('t:'+p)))return false;
    const d=JSON.parse(dec.decode(unb64u(p)));return d.k===key&&d.e>Date.now();
  }catch(e){return false}
}
// validates/normalises price fields. seller = user row of the app owner. cur = existing app (or null)
function pricing(seller,body,cur){
  if(body.price_mode===undefined&&body.price===undefined&&body.currency===undefined)return cur?null:{price_mode:'free',price:0,currency:'USD'};
  const mode=String(body.price_mode!==undefined?body.price_mode:(cur?cur.price_mode:'free'));
  if(!['free','coins','cash'].includes(mode))throw new E(400,'Choose Free, Hex Coins or Real cash.');
  if(mode==='free')return{price_mode:'free',price:0,currency:'USD'};
  const price=Math.round(+(body.price!==undefined?body.price:(cur?cur.price:0)));
  if(mode==='coins'){
    if(!(price>=1&&price<=100000))throw new E(400,'Coin price must be between 1 and 100,000.');
    return{price_mode:'coins',price,currency:''};
  }
  const c=String(body.currency||(cur&&cur.currency)||'USD').toUpperCase();
  if(!CURRENCIES.includes(c))throw new E(400,'Pick a supported currency.');
  if(!(price>=50&&price<=99999900))throw new E(400,'Cash price must be at least 0.50.');
  if(!seller||!(seller.cash_enabled||seller.is_admin))throw new E(403,'Activate a cash key first to sell for real cash.');
  if(!String(seller.payout_details||'').trim())throw new E(400,'Add your account details first so buyers know where to pay.');
  return{price_mode:'cash',price,currency:c};
}
const priceLabel=a=>!a.price_mode||a.price_mode==='free'?'Free':a.price_mode==='coins'?'🪙 '+a.price:money(a.price,a.currency);

const KA='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function genKey(){
  const b=crypto.getRandomValues(new Uint8Array(12)),s=[...b].map(x=>KA[x%32]).join('');
  return 'HEX-'+s.slice(0,4)+'-'+s.slice(4,8)+'-'+s.slice(8,12);
}

// All new endpoints. Returns a Response, or null when the path is not one of ours.
async function apiX(req,env,url,path,ctx,me,body,m,base,now){
  const need=()=>{if(!me)throw new E(401,'Please sign in first.')};
  const admin=()=>{need();if(!me.is_admin)throw new E(403,'Admins only.')};
  let r;

  if(path==='/api/wallet'&&m==='GET'){
    need();
    const [tx,w]=await Promise.all([
      q(env,'select id,amount,kind,note,ref,created_at from coin_tx where user_id=? order by created_at desc limit 40',me.id).all(),
      q(env,'select coins,cash_enabled,payout_details from users where id=?',me.id).first()]);
    return J({coins:w.coins,cash_enabled:Boolean(w.cash_enabled)||Boolean(me.is_admin&&w.payout_details),details:w.payout_details||'',tx:tx.results});
  }

  // ---------- SHOP ----------
  if(path==='/api/shop'&&m==='GET'){
    need();
    const apps=(await q(env,'select id,name,icon_key,status,summary from apps where owner_id=? order by updated_at desc limit 50',me.id).all()).results
      .map(a=>({id:a.id,name:a.name,status:a.status,summary:a.summary,icon_url:a.icon_key?base+'/files/'+a.icon_key:null}));
    const want=url.searchParams.get('app')||(apps[0]&&apps[0].id)||'';
    let owned={},app=null;
    if(want){
      app=await q(env,'select id,name,summary,icon_key,shots from apps where id=? and owner_id=?',want,me.id).first();
      if(app){
        const rows=(await q(env,'select item_id,cfg,enabled from app_items where app_id=?',want).all()).results;
        for(const x of rows){const it=SHOP_BY[x.item_id];if(it)owned[x.item_id]={cfg:cleanCfg(it,jp(x.cfg,{})),enabled:Boolean(x.enabled)}}
      }
    }
    return J({
      coins:await balance(env,me.id),apps,owned,
      app:app?{id:app.id,name:app.name,summary:app.summary||'',icon_url:app.icon_key?base+'/files/'+app.icon_key:null,shots:jp(app.shots,[]).slice(0,3).map(k=>base+'/files/'+k)}:null,
      items:SHOP.map(i=>({id:i.id,emoji:i.emoji,name:i.name,desc:i.desc,price:i.price,cfg:i.cfg,def:i.def,max:i.max||40}))
    });
  }
  if(path==='/api/shop/buy'&&m==='POST'){
    need();
    const it=SHOP_BY[body.item_id];if(!it)throw new E(404,'Item not found.');
    const a=await q(env,'select id,name from apps where id=? and owner_id=?',String(body.app_id||''),me.id).first();
    if(!a)throw new E(403,'Choose one of your own apps first.');
    if(await q(env,'select 1 x from app_items where app_id=? and item_id=?',a.id,it.id).first())throw new E(409,'You already own this for that app.');
    if(!await spendCoins(env,me.id,it.price,'shop',it.name+' for '+a.name,a.id,now))
      throw new E(402,'Not enough Hex Coins. You have '+await balance(env,me.id)+', this costs '+it.price+'.');
    const cfg=cleanCfg(it,body.cfg);
    const ins=await q(env,'insert or ignore into app_items(app_id,item_id,owner_id,cfg,enabled,created_at) values(?,?,?,?,1,?)',a.id,it.id,me.id,JSON.stringify(cfg),now).run();
    if(!(ins.meta&&ins.meta.changes>0)){await giveCoins(env,me.id,it.price,'refund','Refund: '+it.name,a.id,now);throw new E(409,'You already own this for that app.')}
    return J({ok:true,coins:await balance(env,me.id),item:{id:it.id,cfg,enabled:true}});
  }
  if(path==='/api/shop/config'&&m==='POST'){
    need();
    const it=SHOP_BY[body.item_id];if(!it)throw new E(404,'Item not found.');
    const aid=String(body.app_id||'');
    const row=await q(env,'select cfg,enabled from app_items where app_id=? and item_id=? and owner_id=?',aid,it.id,me.id).first();
    if(!row)throw new E(403,'Buy this item first.');
    const cfg=cleanCfg(it,body.cfg,jp(row.cfg,{}));
    const en=body.enabled===undefined?row.enabled:(body.enabled?1:0);
    await q(env,'update app_items set cfg=?,enabled=? where app_id=? and item_id=?',JSON.stringify(cfg),en,aid,it.id).run();
    return J({ok:true,item:{id:it.id,cfg,enabled:Boolean(en)}});
  }

  // ---------- BUY AN APP WITH HEX COINS ----------
  if((r=path.match(/^\/api\/apps\/([\w-]+)\/buy$/))&&m==='POST'){
    need();
    const a=await q(env,'select id,owner_id,name,price_mode,price,status from apps where id=?',r[1]).first();
    if(!a||a.status!=='published')throw new E(404,'App not found');
    if(a.price_mode!=='coins')throw new E(400,'This app is not sold for Hex Coins.');
    if(a.owner_id===me.id)throw new E(400,'This is your own app.');
    if(await q(env,'select 1 x from purchases where user_id=? and app_id=?',me.id,a.id).first())return J({ok:true,already:true,coins:await balance(env,me.id)});
    if(!await spendCoins(env,me.id,a.price,'purchase','Bought '+a.name,a.id,now))
      throw new E(402,'Not enough Hex Coins. You have '+await balance(env,me.id)+', this app costs '+a.price+'.');
    const ins=await q(env,"insert or ignore into purchases(id,user_id,app_id,method,price,currency,created_at) values(?,?,?,'coins',?,'',?)",uid(),me.id,a.id,a.price,now).run();
    if(!(ins.meta&&ins.meta.changes>0)){await giveCoins(env,me.id,a.price,'refund','Refund: '+a.name,a.id,now);return J({ok:true,already:true,coins:await balance(env,me.id)})}
    await giveCoins(env,a.owner_id,a.price,'sale','Sold '+a.name+' to '+me.username,a.id,now);
    await tell(env,a.owner_id,a.id,null,'🪙 '+me.username+' bought '+a.name,'You earned '+a.price+' Hex Coins.');
    return J({ok:true,coins:await balance(env,me.id)});
  }

  // ---------- REAL CASH TRANSFER ----------
  if((r=path.match(/^\/api\/apps\/([\w-]+)\/pay$/))&&m==='GET'){
    need();
    const a=await q(env,'select a.id,a.name,a.owner_id,a.price_mode,a.price,a.currency,a.status,u.payout_details,u.username seller from apps a join users u on u.id=a.owner_id where a.id=?',r[1]).first();
    if(!a||a.status!=='published')throw new E(404,'App not found');
    if(a.price_mode!=='cash')throw new E(400,'This app is not sold for cash.');
    const order=await q(env,'select id,status,reason,note,created_at from cash_orders where buyer_id=? and app_id=? order by created_at desc limit 1',me.id,a.id).first();
    return J({price:a.price,currency:a.currency,label:money(a.price,a.currency),details:a.payout_details||'',seller:a.seller,ref:orderRef(a.id,me.id),order});
  }
  if((r=path.match(/^\/api\/apps\/([\w-]+)\/cash-order$/))&&m==='POST'){
    need();
    const a=await q(env,'select id,name,owner_id,price_mode,price,currency,status from apps where id=?',r[1]).first();
    if(!a||a.status!=='published')throw new E(404,'App not found');
    if(a.price_mode!=='cash')throw new E(400,'This app is not sold for cash.');
    if(a.owner_id===me.id)throw new E(400,'This is your own app.');
    if(await q(env,'select 1 x from purchases where user_id=? and app_id=?',me.id,a.id).first())throw new E(409,'You already own this app.');
    if(await q(env,"select 1 x from cash_orders where buyer_id=? and app_id=? and status='pending'",me.id,a.id).first())throw new E(409,'You already sent a payment for this app. Please wait for the developer to confirm it.');
    if((await q(env,'select count(*) n from cash_orders where buyer_id=? and created_at>?',me.id,now-864e5).first()).n>=10)throw new E(429,'Too many payment notices today. Try again tomorrow.');
    const id=uid();
    await q(env,'insert into cash_orders(id,app_id,buyer_id,seller_id,amount,currency,ref,note,created_at) values(?,?,?,?,?,?,?,?,?)',id,a.id,me.id,a.owner_id,a.price,a.currency,orderRef(a.id,me.id),clip(body.note,200),now).run();
    await tell(env,a.owner_id,a.id,null,'💵 Payment to confirm: '+a.name,me.username+' says they sent '+money(a.price,a.currency)+'. Open Wallet to confirm.');
    return J({ok:true,id});
  }
  if(path==='/api/cash/orders'&&m==='GET'){
    need();
    const [sell,buy]=await Promise.all([
      q(env,'select o.id,o.app_id,o.amount,o.currency,o.ref,o.note,o.status,o.reason,o.created_at,a.name app_name,u.username buyer_name from cash_orders o join apps a on a.id=o.app_id join users u on u.id=o.buyer_id where o.seller_id=? order by (o.status=\'pending\') desc,o.created_at desc limit 50',me.id).all(),
      q(env,'select o.id,o.app_id,o.amount,o.currency,o.ref,o.status,o.reason,o.created_at,a.name app_name,u.username seller_name from cash_orders o join apps a on a.id=o.app_id join users u on u.id=o.seller_id where o.buyer_id=? order by o.created_at desc limit 30',me.id).all()]);
    return J({selling:sell.results,buying:buy.results});
  }
  if((r=path.match(/^\/api\/cash\/orders\/([\w-]+)\/decide$/))&&m==='POST'){
    need();
    const o=await q(env,'select o.*,a.name app_name from cash_orders o join apps a on a.id=o.app_id where o.id=?',r[1]).first();
    if(!o)throw new E(404,'Order not found');
    if(o.seller_id!==me.id&&!me.is_admin)throw new E(403,'Only the developer can confirm this payment.');
    if(o.status!=='pending')throw new E(409,'This payment was already '+o.status+'.');
    const ok=body.decision==='confirm';
    if(!ok&&body.decision!=='reject')throw new E(400,'Choose confirm or reject.');
    const reason=clip(body.reason,300);
    const u=await q(env,"update cash_orders set status=?,reason=?,decided_at=? where id=? and status='pending'",ok?'confirmed':'rejected',reason||null,now,o.id).run();
    if(!(u.meta&&u.meta.changes>0))throw new E(409,'This payment was already handled.');
    if(ok){
      await q(env,"insert or ignore into purchases(id,user_id,app_id,method,price,currency,created_at) values(?,?,?,'cash',?,?,?)",uid(),o.buyer_id,o.app_id,o.amount,o.currency,now).run();
      await tell(env,o.buyer_id,o.app_id,null,'Payment confirmed: '+o.app_name,'You can download it now.');
    }else await tell(env,o.buyer_id,o.app_id,null,'Payment not confirmed: '+o.app_name,reason||'The developer could not find your payment.');
    return J({ok:true});
  }
  if(path==='/api/cash/activate'&&m==='POST'){
    need();
    const details=clip(body.details,500);
    if(details.length<8)throw new E(400,'Enter your account details so buyers know where to pay.');
    if(!me.cash_enabled){
      const key=clip(body.key,40).toUpperCase().replace(/\s+/g,'');
      if(!(me.is_admin&&!key)){
        if(!key)throw new E(400,'Enter your cash key.');
        const kk='k:'+me.id,W=15*60*1000;
        if(await limited(env,kk,5,W,now))throw new E(429,TOO_MANY);
        const u=await q(env,'update cash_keys set used_by=?,used_at=? where code=? and used_by is null',me.id,now,key).run();
        if(!(u.meta&&u.meta.changes>0)){await bump(env,kk,W,now);throw new E(400,'That key is not valid or was already used.')}
      }
    }
    await q(env,'update users set cash_enabled=1,payout_details=? where id=?',details,me.id).run();
    return J({ok:true});
  }

  // ---------- ADMIN: CASH KEYS ----------
  if(path==='/api/admin/cash-keys'&&m==='GET'){
    admin();
    const rows=(await q(env,'select k.code,k.note,k.created_at,k.used_at,u.username used_by_name from cash_keys k left join users u on u.id=k.used_by order by k.created_at desc limit 100').all()).results;
    return J({keys:rows});
  }
  if(path==='/api/admin/cash-keys'&&m==='POST'){
    admin();
    const n=Math.min(20,Math.max(1,Math.round(+body.count||1))),note=clip(body.note,60),keys=[];
    for(let i=0;i<n;i++)keys.push(genKey());
    await env.DB.batch(keys.map(k=>q(env,'insert into cash_keys(code,note,created_by,created_at) values(?,?,?,?)',k,note,me.id,now)));
    return J({keys});
  }
  if((r=path.match(/^\/api\/admin\/cash-keys\/([\w-]+)$/))&&m==='DELETE'){
    admin();
    await q(env,'delete from cash_keys where code=? and used_by is null',r[1]).run();
    return J({ok:true});
  }

  // ---------- DOWNLOAD TICKET (paid apps) ----------
  if((r=path.match(/^\/api\/versions\/([\w-]+)\/ticket$/))&&m==='POST'){
    need();
    const v=await q(env,'select v.apk_key,v.status,a.id app_id,a.owner_id,a.price_mode from versions v join apps a on a.id=v.app_id where v.id=?',r[1]).first();
    if(!v||!v.apk_key)throw new E(404,'Download not available.');
    if(v.status!=='approved'&&!(me.is_admin||v.owner_id===me.id))throw new E(403,'Not available.');
    if(!await owns(env,me,{id:v.app_id,owner_id:v.owner_id,price_mode:v.price_mode}))throw new E(402,'Buy this app to download it.');
    return J({url:base+'/files/'+v.apk_key+'?dl=1&t='+await signTicket(env,v.apk_key,10*60*1000)});
  }
  return null;
}

export default{
  async fetch(req,env,ctx){
    if(req.method==='OPTIONS')return new Response(null,{status:204,headers:CORS});
    const url=new URL(req.url),path=url.pathname;
    try{
      const miss=['DB','JWT_SECRET','GITHUB_TOKEN','GITHUB_OWNER','GITHUB_REPO'].filter(k=>!env[k]);
      if(miss.length)throw new E(500,'Setup incomplete. Missing: '+miss.join(', '));
      await ensureSchema(env);
      if(path.startsWith('/files/'))return await file(req,env,sd(path.slice(7)),url);
      if(path.startsWith('/a/'))return await sharePage(env,url,sd(path.slice(3)));
      if(!path.startsWith('/api/'))return env.ASSETS?env.ASSETS.fetch(req):J({name:'HEXSTORE API',ok:true});
      return await api(req,env,url,path,ctx);
    }catch(e){return J({error:e.s?e.message:'Server error: '+(e.message||'')},e.s||500)}
  }
};

const GH=env=>({Authorization:'Bearer '+env.GITHUB_TOKEN,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'hexstore'});
const gh=(env,method,path,body)=>fetch('https://api.github.com/repos/'+env.GITHUB_OWNER+'/'+env.GITHUB_REPO+path,{method,headers:GH(env),body:body?JSON.stringify(body):undefined});
let REL=null;
async function release(env){
  const tag='files-'+new Date().toISOString().slice(0,7);
  if(REL&&REL.tag===tag)return REL;
  let r=await gh(env,'GET','/releases/tags/'+tag);
  if(r.status===404){
    r=await gh(env,'POST','/releases',{tag_name:tag,name:'Files '+tag,body:'HEXSTORE uploads',draft:false,prerelease:false,make_latest:'false'});
    if(r.status===422)r=await gh(env,'GET','/releases/tags/'+tag);
  }
  const j=await r.json().catch(()=>({}));
  if(!r.ok)throw new E(502,'GitHub storage error: '+(j.message||r.status));
  REL={id:j.id,tag};
  return REL;
}
async function ghUpload(env,relId,name,type,stream,len){
  let body=stream;
  if(typeof FixedLengthStream!=='undefined'){const f=new FixedLengthStream(len);stream.pipeTo(f.writable);body=f.readable}
  const r=await fetch('https://uploads.github.com/repos/'+env.GITHUB_OWNER+'/'+env.GITHUB_REPO+'/releases/'+relId+'/assets?name='+encodeURIComponent(name),{method:'POST',headers:{...GH(env),'Content-Type':type},body,duplex:'half'});
  const j=await r.json().catch(()=>({}));
  if(!r.ok)throw new E(502,'GitHub upload failed: '+(j.message||r.status));
  return j;
}
async function file(req,env,key,url){
  const f=await q(env,'select tag,asset,orig_name,size from files where key=?',key).first();
  if(!f)throw new E(404,'File not found');
  let priv=false;
  if(/\.apk$/i.test(key)){
    const g=await q(env,'select a.id,a.owner_id,a.price_mode from versions v join apps a on a.id=v.app_id where v.apk_key=? limit 1',key).first();
    if(g&&g.price_mode&&g.price_mode!=='free'){
      let ok=await checkTicket(env,url.searchParams.get('t'),key);
      if(!ok)ok=await owns(env,await who(env,req),g);
      if(!ok)throw new E(402,'This is a paid app. Buy it to download.');
      priv=true;
    }
  }
  const target='https://github.com/'+env.GITHUB_OWNER+'/'+env.GITHUB_REPO+'/releases/download/'+f.tag+'/'+encodeURIComponent(f.asset);
  if(!priv&&url.searchParams.get('dl')!=='1')return new Response(null,{status:302,headers:{...CORS,'Location':target,'Cache-Control':'public, max-age=3600'}});
  const range=req.headers.get('Range');
  const r=await fetch(target,{redirect:'follow',headers:range?{Range:range}:{}});
  if(!(r.ok||r.status===206)||!r.body)throw new E(502,'Download not available right now. Try again.');
  const name=String(f.orig_name||f.asset).replace(/[^\w.\- ]+/g,'_');
  const h={...CORS,'Content-Type':/\.apk$/i.test(f.asset)?'application/vnd.android.package-archive':(r.headers.get('Content-Type')||'application/octet-stream'),'Content-Length':r.headers.get('Content-Length')||String(f.size||''),'Accept-Ranges':'bytes','Content-Disposition':'attachment; filename="'+name+'"','Cache-Control':priv?'private, no-store':'public, max-age=3600'};
  if(r.status===206&&r.headers.get('Content-Range'))h['Content-Range']=r.headers.get('Content-Range');
  return new Response(r.body,{status:r.status===206?206:200,headers:h});
}

async function api(req,env,url,path,ctx){
  const m=req.method,base=url.origin,me=await who(env,req),now=Date.now();
  const body=(m==='POST'||m==='PATCH'||m==='PUT')&&path!=='/api/upload'?await req.json().catch(()=>({})):{};
  const need=()=>{if(!me)throw new E(401,'Please sign in first.')};
  let r;
  const xr=await apiX(req,env,url,path,ctx,me,body,m,base,now);
  if(xr)return xr;
  // short server-side cache for the public (signed-out) app list: much faster for most visitors
  const cacheKey=(m==='GET'&&!req.headers.get('Authorization')&&path==='/api/apps'&&!url.searchParams.get('mine')&&!url.searchParams.get('status'))?new Request(url.toString()):null;
  if(cacheKey&&typeof caches!=='undefined'&&caches.default){
    try{const hit=await caches.default.match(cacheKey);if(hit)return new Response(hit.body,{status:200,headers:{...CORS,'Content-Type':'application/json','Cache-Control':'no-cache','X-Cache':'HIT'}})}catch(e){}
  }

  if(path==='/api/register'&&m==='POST'){
    const email=clip(body.email,120).toLowerCase(),pw=String(body.password||''),kR='r:'+ipOf(req);
    if(await limited(env,kR,5,36e5,now))throw new E(429,'Too many new accounts from this network. Try again later.');
    if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))throw new E(400,'Enter a valid email.');
    if(pw.length<6)throw new E(400,'Password must be at least 6 characters.');
    if(await q(env,'select 1 x from users where email=?',email).first())throw new E(409,'That email already has an account. Sign in instead.');
    const first=(await q(env,'select count(*) n from users').first()).n===0;
    await bump(env,kR,36e5,now);
    const id=uid(),salt=hex(crypto.getRandomValues(new Uint8Array(16)));
    const name=clip(body.username,30)||email.split('@')[0].slice(0,30);
    try{await q(env,'insert into users(id,email,pass_hash,username,is_admin,created_at) values(?,?,?,?,?,?)',id,email,salt+':'+await hashPw(pw,salt),name,first?1:0,now).run()}
    catch(e){if(/UNIQUE/i.test(String(e.message)))throw new E(409,'That email already has an account. Sign in instead.');throw e}
    const gift=await welcome(env,id,now);
    return J({token:await mint(env,id),welcome:gift,user:pub({id,email,username:name,bio:'',is_admin:first?1:0,email_alerts:1,coins:gift?WELCOME_COINS:0},base)});
  }
  if(path==='/api/login'&&m==='POST'){
    const email=clip(body.email,120).toLowerCase(),ip=ipOf(req),kE='l:'+email+'|'+ip,kI='i:'+ip,W=15*60*1000;
    if(await limited(env,kE,5,W,now)||await limited(env,kI,30,W,now))throw new E(429,TOO_MANY);
    const fail=async()=>{await bump(env,kE,W,now);await bump(env,kI,W,now);await q(env,'delete from login_attempts where window_start<?',now-864e5).run();throw new E(401,'Wrong email or password.')};
    const u=await q(env,'select * from users where email=?',email).first();
    if(!u){await hashPw(String(body.password||''),'00'.repeat(16));await fail()}
    const [salt,h]=u.pass_hash.split(':');
    if(await hashPw(String(body.password||''),salt)!==h)await fail();
    await clearKey(env,kE);
    const gift=await welcome(env,u.id,now);if(gift)u.coins=(+u.coins||0)+WELCOME_COINS;
    return J({token:await mint(env,u.id),welcome:gift,user:pub(u,base)});
  }
  if(path==='/api/me'&&m==='GET'){
    need();
    const gift=await welcome(env,me.id,now);if(gift)me.coins=(+me.coins||0)+WELCOME_COINS;
    const s=await q(env,'select (select count(*) from apps where owner_id=?1) apps,(select coalesce(sum(downloads),0) from apps where owner_id=?1) downloads,(select count(*) from favorites where user_id=?1) favorites,(select count(*) from notifications where user_id=?1 and is_read=0) unread,(select count(*) from dev_follows where dev_id=?1) followers,(select count(*) from dev_follows where follower_id=?1) following',me.id).first();
    const c=await q(env,'select created_at from users where id=?',me.id).first();
    return J({user:{...pub(me,base),created_at:c.created_at},stats:s,welcome:gift});
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

  // Help Center: notifies admin bell 🔔
  if(path==='/api/support'&&m==='POST'){
    const subject=clip(body.subject,100),message=clip(body.message,2000),email=clip(body.email,120).toLowerCase(),name=clip(body.name,60);
    if(!subject||!message)throw new E(400,'Subject and message are required.');
    const id=uid(),userId=me?me.id:null;
    const kS='s:'+(userId||ipOf(req));
    if(await limited(env,kS,5,36e5,now))throw new E(429,'Too many messages. Try again later.');
    await bump(env,kS,36e5,now);
    await q(env,'insert into support_tickets(id,user_id,name,email,subject,message,created_at) values(?,?,?,?,?,?,?)',id,userId,name,email,subject,message,now).run();
    await q(env,"insert into notifications(id,user_id,title,body,created_at) select lower(hex(randomblob(16))),u.id,'📩 Support: '||?1,?2,?3 from users u where u.is_admin=1",subject,(name||'User')+': '+message.slice(0,80),now).run();
    return J({ok:true});
  }
  if(path==='/api/admin/support'&&m==='GET'){
    need();if(!me.is_admin)throw new E(403,'Admins only.');
    const rows=(await q(env,"select * from support_tickets where status='open' order by created_at desc limit 50").all()).results;
    return J({tickets:rows});
  }
  if((r=path.match(/^\/api\/admin\/support\/([\w-]+)\/resolve$/))&&m==='POST'){
    need();if(!me.is_admin)throw new E(403,'Admins only.');
    await q(env,"update support_tickets set status='resolved' where id=?",r[1]).run();
    return J({ok:true});
  }

  // Developer Profile & Follows
  if((r=path.match(/^\/api\/users\/([\w-]+)$/))&&m==='GET'){
    const u=await q(env,'select id,username,bio,avatar_key,created_at,is_admin from users where id=?',r[1]).first();
    if(!u)throw new E(404,'User not found');
    const s=await q(env,"select (select count(*) from apps where owner_id=?1 and status='published') apps,(select coalesce(sum(downloads),0) from apps where owner_id=?1 and status='published') downloads,(select count(*) from dev_follows where dev_id=?1) followers,(select count(*) from dev_follows where follower_id=?1) following,(select count(*) from community_posts where user_id=?1) posts",r[1]).first();
    const rows=(await q(env,SEL+" where a.status='published' and a.owner_id=? order by a.updated_at desc limit 100",r[1]).all()).results;
    let is_following=false;
    if(me)is_following=Boolean(await q(env,'select 1 x from dev_follows where follower_id=? and dev_id=?',me.id,r[1]).first());
    const isPrime=Boolean(u.is_admin||(s.downloads>=500));
    return J({user:{id:u.id,username:u.username,bio:u.bio||'',is_admin:Boolean(u.is_admin),created_at:u.created_at,avatar_url:u.avatar_key?base+'/files/'+u.avatar_key:null},stats:s,is_following,is_prime:isPrime,can_post:s.apps>0||Boolean(u.is_admin),apps:rows.map(a=>lite(a,base))});
  }
  if((r=path.match(/^\/api\/users\/([\w-]+)\/(followers|following)$/))&&m==='GET'){
    const fol=r[2]==='followers';
    const rows=(await q(env,'select u.id,u.username,u.bio,u.avatar_key,u.is_admin,(select count(*) from dev_follows where dev_id=u.id) followers,(select coalesce(sum(downloads),0) from apps where owner_id=u.id and status=\'published\') downloads from dev_follows f join users u on u.id='+(fol?'f.follower_id':'f.dev_id')+' where '+(fol?'f.dev_id':'f.follower_id')+'=? order by f.created_at desc limit 200',r[1]).all()).results;
    return J({users:rows.map(x=>({id:x.id,username:x.username,bio:x.bio||'',is_admin:Boolean(x.is_admin),followers:+(x.followers||0)+(x.is_admin?256789:0),downloads:+(x.downloads||0),avatar_url:x.avatar_key?base+'/files/'+x.avatar_key:null}))});
  }
  if((r=path.match(/^\/api\/users\/([\w-]+)\/follow$/))&&m==='POST'){
    need();
    if(r[1]===me.id)throw new E(400,"You cannot follow yourself.");
    const t=await q(env,'select id from users where id=?',r[1]).first();
    if(!t)throw new E(404,'User not found');
    if(body.on){
      const ins=await q(env,'insert or ignore into dev_follows(follower_id,dev_id,created_at) values(?,?,?)',me.id,r[1],now).run();
      if(ins.meta&&ins.meta.changes>0){
        const recent=await q(env,'select 1 x from notifications where user_id=? and from_user=? and created_at>?',r[1],me.id,now-864e5).first();
        if(!recent)await q(env,'insert into notifications(id,user_id,from_user,title,body,created_at) values(?,?,?,?,?,?)',uid(),r[1],me.id,me.username+' started following you','Tap to view their profile.',now).run();
      }
    }else await q(env,'delete from dev_follows where follower_id=? and dev_id=?',me.id,r[1]).run();
    const c=(await q(env,'select count(*) n from dev_follows where dev_id=?',r[1]).first()).n;
    return J({ok:true,followers:c});
  }

  // Community Feed & Likes
  if((r=path.match(/^\/api\/users\/([\w-]+)\/posts$/))&&m==='GET'){
    const devId=r[1];
    const published=(await q(env,"select count(*) n from apps where owner_id=? and status='published'",devId).first()).n;
    const u=await q(env,'select is_admin from users where id=?',devId).first();
    const can_post=published>0||Boolean(u&&u.is_admin);
    const rows=(await q(env,'select p.*,(select count(*) from community_likes l where l.post_id=p.id) likes_count from community_posts p where p.user_id=? order by p.created_at desc limit 50',devId).all()).results;
    let likedSet=new Set();
    if(me&&rows.length){
      const lks=(await q(env,'select post_id from community_likes where user_id=? and post_id in ('+rows.map(()=>'?').join(',')+')',me.id,...rows.map(x=>x.id)).all()).results;
      lks.forEach(x=>likedSet.add(x.post_id));
    }
    return J({can_post,posts:rows.map(x=>({id:x.id,content:x.content,image_url:x.image_key?base+'/files/'+x.image_key:null,created_at:x.created_at,likes_count:x.likes_count,is_liked:likedSet.has(x.id)}))});
  }
  if(path==='/api/community/posts'&&m==='POST'){
    need();
    const pubCount=(await q(env,"select count(*) n from apps where owner_id=? and status='published'",me.id).first()).n;
    if(!me.is_admin&&pubCount===0)throw new E(403,'Only publishers with at least 1 approved app can post to a community.');
    const content=clip(body.content,2000),img=body.image_key||null;
    if(!content)throw new E(400,'Content cannot be empty.');
    if(img&&!mine(img,me.id))throw new E(400,'Invalid image.');
    const id=uid();
    await q(env,'insert into community_posts(id,user_id,content,image_key,created_at) values(?,?,?,?,?)',id,me.id,content,img,now).run();
    await q(env,"insert into notifications(id,user_id,from_user,title,body,created_at) select lower(hex(randomblob(16))),f.follower_id,?1,?2,?3,?4 from dev_follows f where f.dev_id=?1 limit 5000",me.id,'📢 '+me.username+' posted in their community',content.slice(0,100),now).run();
    return J({id,ok:true});
  }
  if((r=path.match(/^\/api\/community\/posts\/([\w-]+)$/))&&m==='DELETE'){
    need();
    const p=await q(env,'select * from community_posts where id=?',r[1]).first();
    if(!p)throw new E(404,'Post not found');
    if(p.user_id!==me.id&&!me.is_admin)throw new E(403,'Not allowed.');
    await q(env,'delete from community_posts where id=?',p.id).run();
    await q(env,'delete from community_likes where post_id=?',p.id).run();
    if(p.image_key)await delFile(env,p.image_key);
    return J({ok:true});
  }
  if((r=path.match(/^\/api\/community\/posts\/([\w-]+)\/like$/))&&m==='POST'){
    need();
    if(!await q(env,'select 1 x from community_posts where id=?',r[1]).first())throw new E(404,'Post not found');
    if(body.on)await q(env,'insert or ignore into community_likes(post_id,user_id) values(?,?)',r[1],me.id).run();
    else await q(env,'delete from community_likes where post_id=? and user_id=?',r[1],me.id).run();
    const c=(await q(env,'select count(*) n from community_likes where post_id=?',r[1]).first()).n;
    return J({ok:true,likes:c});
  }

  // Uploads
  if(path==='/api/upload'&&m==='POST'){
    need();
    const kind=url.searchParams.get('kind'),len=+req.headers.get('Content-Length');
    const name=clip(sd(req.headers.get('X-Filename')||'file'),120)||'file';
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
    if(!me.is_admin){
      const day=(await q(env,"select coalesce(sum(case when asset like '%.apk' then 1 else 0 end),0) apks,coalesce(sum(case when asset like '%.apk' then 0 else 1 end),0) imgs from files where owner_id=? and created_at>?",me.id,now-864e5).first());
      if(kind==='apk'&&day.apks>=10)throw new E(429,'Upload limit reached: 10 APKs per day. Try again tomorrow.');
      if(kind==='image'&&day.imgs>=40)throw new E(429,'Upload limit reached: 40 images per day. Try again tomorrow.');
      const tot=(await q(env,'select coalesce(sum(size),0) s from files where owner_id=?',me.id).first()).s;
      if(tot+len>1024*1024*1024)throw new E(413,'Storage limit reached (1 GB). Delete old apps or files first.');
    }
    const key=me.id+'/'+uid()+ext;
    const rel=await release(env);
    const asset=uid().slice(0,8)+'-'+(name.replace(/\.[^.]+$/,'').replace(/[^a-zA-Z0-9]+/g,'-').replace(/^-|-$/g,'').slice(0,40)||'file')+ext;
    let up;try{up=await ghUpload(env,rel.id,asset,type,req.body,len)}catch(e){REL=null;throw e}
    await q(env,'insert into files(key,owner_id,tag,asset,asset_id,orig_name,size,created_at) values(?,?,?,?,?,?,?,?)',key,me.id,rel.tag,asset,up.id,name,len,now).run();
    return J({key,size:len,url:base+'/files/'+key});
  }

  // Apps
  if(path==='/api/apps'&&m==='GET'){
    const p=url.searchParams,text=clip(p.get('q'),60);let where,b=[];
    if(p.get('mine')){need();where='a.owner_id=?';b=[me.id]}
    else if(p.get('status')==='pending'){need();if(!me.is_admin)throw new E(403,'Admins only.');where="a.status='pending'"}
    else where="a.status='published'";
    if(text){const lk='%'+text.replace(/[\\%_]/g,'\\$&')+'%';where+=" and (a.name like ? escape '\\' or a.category like ? escape '\\' or a.summary like ? escape '\\')";b.push(lk,lk,lk)}
    const cat=clip(p.get('cat'),40);
    if(cat&&cat!=='All'){where+=' and a.category=?';b.push(cat)}
    const rows=(await q(env,SEL+' where '+where+' order by a.updated_at desc limit 100',...b).all()).results;
    const out={apps:rows.map(a=>lite(a,base))};
    if(cacheKey&&typeof caches!=='undefined'&&caches.default&&ctx&&ctx.waitUntil)ctx.waitUntil(caches.default.put(cacheKey,new Response(JSON.stringify(out),{headers:{'Content-Type':'application/json','Cache-Control':'public, max-age=20'}})).catch(()=>{}));
    return J(out);
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
    if(!draft&&shots.length<1)throw new E(400,'Add at least 1 screenshot.');
    const pr=pricing(me,body,null);
    const id=uid(),status=draft?'draft':'pending';
    await q(env,'insert into apps(id,owner_id,name,category,description,summary,origin,source_url,is_exclusive,tags,icon_key,shots,status,created_at,updated_at,price_mode,price,currency) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
    id,me.id,name,cat,desc,sum,body.origin||null,clip(body.source_url,200)||null,body.is_exclusive?1:0,JSON.stringify((Array.isArray(body.tags)?body.tags:[]).map(t=>clip(t,24)).slice(0,8)),body.icon_key||null,JSON.stringify(shots),status,now,now,pr.price_mode,pr.price,pr.currency).run();
    return J({id,status});
  }
  if((r=path.match(/^\/api\/apps\/([\w-]+)$/))){
    const id=r[1];
    const a=await q(env,SEL+' where a.id=?',id).first();
    if(!a)throw new E(404,'App not found');
    const owner=Boolean(me&&me.id===a.owner_id),admin=Boolean(me&&me.is_admin);
    if(m==='GET'){
      if(!(a.status==='published'||owner||admin))throw new E(404,'App not found');
      const full=owner||admin,paid=a.price_mode&&a.price_mode!=='free';
      const [vrs,rvs,dist,fol,fav,mr,pur,fx,ord]=await Promise.all([
        q(env,full?'select * from versions where app_id=? order by version_code desc':"select * from versions where app_id=? and status='approved' order by version_code desc",id).all(),
        q(env,'select r.id,r.rating,r.comment,r.created_at,r.reply,r.reply_at,u.username,u.avatar_key,u.is_admin from reviews r join users u on u.id=r.user_id where r.app_id=? order by r.created_at desc limit 100',id).all(),
        q(env,'select rating,count(*) n from reviews where app_id=? group by rating',id).all(),
        me?q(env,'select 1 x from follows where user_id=? and app_id=?',me.id,id).first():null,
        me?q(env,'select 1 x from favorites where user_id=? and app_id=?',me.id,id).first():null,
        me?q(env,'select rating,comment from reviews where user_id=? and app_id=?',me.id,id).first():null,
        (me&&paid&&!full)?q(env,'select 1 x from purchases where user_id=? and app_id=?',me.id,id).first():null,
        q(env,'select item_id,cfg from app_items where app_id=? and enabled=1',id).all(),
        (me&&a.price_mode==='cash'&&!full)?q(env,'select id,status,reason,created_at from cash_orders where buyer_id=? and app_id=? order by created_at desc limit 1',me.id,id).first():null
      ]);
      const owned=!paid||full||Boolean(pur);
      const vs=vrs.results.map(v=>({...v,apk_key:owned?v.apk_key:'',apk_url:owned&&v.apk_key?base+'/files/'+v.apk_key:''}));
      const rv=rvs.results.map(x=>({id:x.id,reply:x.reply||'',reply_at:x.reply_at||null,rating:x.rating,comment:x.comment,created_at:x.created_at,username:x.username,is_admin:Boolean(x.is_admin),avatar_url:x.avatar_key?base+'/files/'+x.avatar_key:null}));
      return J({app:shape(a,base),versions:vs,reviews:rv,dist:dist.results,following:Boolean(fol),favorited:Boolean(fav),my_review:mr||null,is_owner:owner,owned,my_order:ord||null,fx:fxList(fx.results)});
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
      if(Array.isArray(body.shots)){const ns=body.shots.filter(k=>mine(k,a.owner_id)).slice(0,8);for(const k of jp(a.shots,[]))if(!ns.includes(k))await delFile(env,k);f.shots=JSON.stringify(ns)}
      if(body.status!==undefined){
        if(admin&&['draft','pending','published','rejected'].includes(body.status))f.status=body.status;
        else if(owner&&['draft','pending'].includes(body.status)&&a.status!=='published')f.status=(body.status==='pending'&&admin)?'published':body.status;
      }
      if(f.status&&f.status!==a.status&&['pending','published'].includes(f.status)){
        const nowShots=f.shots!==undefined?JSON.parse(f.shots):jp(a.shots,[]);
        if(nowShots.length<1)throw new E(400,'Add at least 1 screenshot first.');
      }
      const seller=a.owner_id===me.id?me:await q(env,'select cash_enabled,payout_details,is_admin from users where id=?',a.owner_id).first();
      const pr=pricing(seller,body,a);if(pr)Object.assign(f,pr);
      if(f.status&&f.status!==a.status&&['pending','published'].includes(f.status)){
        if(!(await q(env,'select count(*) n from versions where app_id=?',id).first()).n)throw new E(400,'Upload an APK version first.');
      }
      const keys=Object.keys(f);
      if(keys.length){await q(env,'update apps set '+keys.map(k=>k+'=?').join(',')+',updated_at=? where id=?',...keys.map(k=>f[k]),now,id).run()}
      if(f.status==='pending'&&a.status!=='pending'){
        const lv=await q(env,"select * from versions where app_id=? and status='pending' order by version_code desc limit 1",id).first();
        if(lv)await alertAdmins(env,ctx,{...a,status:'pending'},lv,me.username);
      }
      if(f.status==='published'){await q(env,"update versions set status='approved' where app_id=? and status='pending'",id).run();await retireOld(env,id)}
      return J({ok:true});
    }
    if(m==='DELETE'){
      const vs=(await q(env,'select apk_key from versions where app_id=?',id).all()).results;
      const keys=[...vs.map(v=>v.apk_key),a.icon_key,...jp(a.shots,[])].filter(Boolean);
      await q(env,'delete from apps where id=?',id).run();
      const job=Promise.all(keys.map(k=>delFile(env,k)));
      if(ctx&&ctx.waitUntil)ctx.waitUntil(job);else await job;
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
    const fr=await q(env,'select size from files where key=?',body.apk_key).first();
    if(!fr)throw new E(400,'Upload the APK first.');
    const dup=await q(env,'select id,version_code,status,app_id from versions where apk_key=?',body.apk_key).first();
    if(dup){if(dup.app_id===a.id)return J({id:dup.id,version_code:dup.version_code,status:dup.status});throw new E(409,'That APK is already used by another app.')}
    const code=(await q(env,'select coalesce(max(version_code),0)+1 c from versions where app_id=?',a.id).first()).c;
    const vid=uid(),log=clip(body.changelog,2000),st=me.is_admin?'approved':'pending';
    await q(env,'insert into versions(id,app_id,version_name,version_code,changelog,apk_key,size,status,created_at) values(?,?,?,?,?,?,?,?,?)',vid,a.id,vn,code,log,body.apk_key,+fr.size||0,st,now).run();
    await q(env,'update apps set updated_at=? where id=?',now,a.id).run();
    if(st==='approved'){
      if(a.status==='pending'&&a.owner_id===me.id){await q(env,"update apps set status='published',reject_reason=null where id=?",a.id).run();a.status='published'}
      await announce(env,ctx,base,a,{id:vid,version_name:vn,changelog:log});await retireOld(env,a.id)
    }else if(a.status!=='draft')await alertAdmins(env,ctx,a,{id:vid,version_name:vn},me.username);
    return J({id:vid,version_code:code,status:st});
  }
  if((r=path.match(/^\/api\/versions\/([\w-]+)\/download$/))&&m==='POST'){
    const v=await q(env,"select v.app_id,a.owner_id,a.price_mode from versions v join apps a on a.id=v.app_id where v.id=? and v.status='approved' and a.status='published'",r[1]).first();
    if(v){
      if(!await owns(env,me,{id:v.app_id,owner_id:v.owner_id,price_mode:v.price_mode}))throw new E(402,'Buy this app to download it.');
      const dk='d:'+ipOf(req)+':'+r[1];
      if(!(me&&me.id===v.owner_id)&&!await limited(env,dk,1,6e5,now)){
        await bump(env,dk,6e5,now);
        await env.DB.batch([q(env,'update versions set downloads=downloads+1 where id=?',r[1]),q(env,'update apps set downloads=downloads+1 where id=?',v.app_id)]);
        if(Math.random()<0.02)await q(env,'delete from login_attempts where window_start<?',now-864e5).run();
      }
    }
    return J({ok:true});
  }
  if((r=path.match(/^\/api\/apps\/([\w-]+)\/(follow|favorite)$/))&&m==='POST'){
    need();
    const t=r[2]==='follow'?'follows':'favorites';
    if(!await q(env,"select 1 x from apps where id=? and (status='published' or owner_id=?)",r[1],me.id).first())throw new E(404,'App not found');
    if(body.on)await q(env,'insert or ignore into '+t+'(user_id,app_id) values(?,?)',me.id,r[1]).run();
    else await q(env,'delete from '+t+' where user_id=? and app_id=?',me.id,r[1]).run();
    return J({ok:true});
  }
  if((r=path.match(/^\/api\/apps\/([\w-]+)\/reviews$/))&&m==='POST'){
    need();
    const ra=await q(env,'select owner_id,status from apps where id=?',r[1]).first();
    if(!ra||ra.status!=='published')throw new E(404,'App not found');
    if(ra.owner_id===me.id)throw new E(400,'You cannot review your own app.');
    const rating=Math.round(+body.rating);
    if(!(rating>=1&&rating<=5))throw new E(400,'Tap a star to rate.');
    await q(env,'insert into reviews(id,app_id,user_id,rating,comment,created_at) values(?,?,?,?,?,?) on conflict(app_id,user_id) do update set rating=excluded.rating,comment=excluded.comment,created_at=excluded.created_at',uid(),r[1],me.id,rating,clip(body.comment,1000),now).run();
    return J({ok:true});
  }
  if((r=path.match(/^\/api\/reviews\/([\w-]+)\/reply$/))&&m==='POST'){
    need();
    const rv=await q(env,'select r.id,r.user_id,r.app_id,r.reply,a.owner_id,a.name from reviews r join apps a on a.id=r.app_id where r.id=?',r[1]).first();
    if(!rv)throw new E(404,'Review not found');
    if(rv.owner_id!==me.id)throw new E(403,'Only the developer of this app can reply.');
    const txt=clip(body.reply,500);
    if(!txt){await q(env,'update reviews set reply=null,reply_at=null where id=?',rv.id).run();return J({ok:true,removed:true})}
    await q(env,'update reviews set reply=?,reply_at=? where id=?',txt,now,rv.id).run();
    if(!rv.reply&&rv.user_id!==me.id)await tell(env,rv.user_id,rv.app_id,null,rv.name+': developer replied','Tap to read the reply to your review.');
    return J({ok:true});
  }
  if(path==='/api/installs'&&m==='POST'){
    need();
    const items=(Array.isArray(body.items)?body.items:[body]).slice(0,50);
    const stm=[];
    for(const it of items){
      const aid=String((it&&it.app_id)||'');
      if(!aid)continue;
      stm.push(q(env,'insert into installs(user_id,app_id,version_code,version_name,updated_at) select ?1,?2,?3,?4,?5 where exists(select 1 from apps where id=?2) on conflict(user_id,app_id) do update set version_name=case when excluded.version_code>=installs.version_code then excluded.version_name else installs.version_name end,version_code=max(installs.version_code,excluded.version_code),updated_at=?5',me.id,aid,Math.max(0,Math.floor(+it.version_code||0)),clip(it.version_name,30),now));
    }
    if(stm.length)await env.DB.batch(stm);
    return J({ok:true});
  }
  if((r=path.match(/^\/api\/installs\/([\w-]+)$/))&&m==='DELETE'){
    need();await q(env,'delete from installs where user_id=? and app_id=?',me.id,r[1]).run();return J({ok:true});
  }
  if(path==='/api/favorites'&&m==='GET'){
    need();
    const rows=(await q(env,SEL+" where a.status='published' and a.id in (select app_id from favorites where user_id=?) order by a.updated_at desc",me.id).all()).results;
    return J({apps:rows.map(a=>lite(a,base))});
  }
  if(path==='/api/admin/queue'&&m==='GET'){
    need();if(!me.is_admin)throw new E(403,'Admins only.');
    if(url.searchParams.get('count')){
      const c=await q(env,"select (select count(*) from apps where status='pending') a,(select count(*) from versions v join apps a on a.id=v.app_id where v.status='pending' and a.status='published') v").first();
      return J({count:(c.a||0)+(c.v||0)});
    }
    const [pa,pv]=await Promise.all([
      q(env,SEL+" where a.status='pending' order by a.updated_at asc limit 50").all(),
      q(env,"select v.* from versions v join apps a on a.id=v.app_id where v.status='pending' and a.status='published' order by v.created_at asc limit 50").all()]);
    const ids=[...new Set(pv.results.map(v=>v.app_id))];
    const [lv,pvApps]=await Promise.all([
      pa.results.length?q(env,"select * from versions where status='pending' and app_id in ("+pa.results.map(()=>'?').join(',')+") order by version_code desc",...pa.results.map(a=>a.id)).all():{results:[]},
      ids.length?q(env,SEL+' where a.id in ('+ids.map(()=>'?').join(',')+')',...ids).all():{results:[]}]);
    const latest={};for(const v of lv.results)if(!latest[v.app_id])latest[v.app_id]=v;
    const byId={};for(const a of pvApps.results)byId[a.id]=a;
    const vurl=async(v,a)=>!v?null:{...v,apk_url:base+'/files/'+v.apk_key+(a.price_mode&&a.price_mode!=='free'?'?dl=1&t='+await signTicket(env,v.apk_key,3600e3):'')};
    const items=[];
    for(const a of pa.results)items.push({type:'app',app:shape(a,base),version:await vurl(latest[a.id],a),uploader:{username:a.owner_name,email:(await q(env,'select email from users where id=?',a.owner_id).first()||{}).email||''}});
    for(const v of pv.results){const a=byId[v.app_id];if(!a)continue;items.push({type:'version',app:shape(a,base),version:await vurl(v,a),uploader:{username:a.owner_name,email:(await q(env,'select email from users where id=?',a.owner_id).first()||{}).email||''}})}
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
          await q(env,"update versions set status='rejected',reject_reason='Replaced by newer version.' where app_id=? and status='pending'",a.id).run();
          await retireOld(env,a.id);
        }
        await tell(env,a.owner_id,a.id,null,a.name+' is live!','Your app was approved and is in the store.');
      }else{
        await q(env,"update apps set status='rejected',reject_reason=?,updated_at=? where id=?",reason,now,a.id).run();
        await tell(env,a.owner_id,a.id,null,a.name+' not approved','Reason: '+reason);
      }
    }else if(body.type==='version'){
      const v=await q(env,'select * from versions where id=?',body.id).first();if(!v)throw new E(404,'Version not found');
      const a=await q(env,'select * from apps where id=?',v.app_id).first();
      if(ok){
        await q(env,"update versions set status='approved',reject_reason=null where id=?",v.id).run();
        await q(env,'update apps set updated_at=? where id=?',now,a.id).run();
        await tell(env,a.owner_id,a.id,v.id,a.name+' v'+v.version_name+' approved','Update is live and followers notified.');
        await announce(env,ctx,base,a,{id:v.id,version_name:v.version_name,changelog:v.changelog});
        await retireOld(env,a.id);
      }else{
        await q(env,"update versions set status='rejected',reject_reason=? where id=?",reason,v.id).run();
        await tell(env,a.owner_id,a.id,v.id,a.name+' v'+v.version_name+' not approved','Reason: '+reason);
      }
    }else throw new E(400,'Unknown item.');
    return J({ok:true});
  }
  if(path==='/api/notifications'&&m==='GET'){
    need();
    const rows=(await q(env,'select * from notifications where user_id=? order by created_at desc limit ?',me.id,url.searchParams.get('peek')?1:50).all()).results;
    const un=(await q(env,'select count(*) n from notifications where user_id=? and is_read=0',me.id).first()).n;
    return J({notifications:rows,unread:un});
  }
  if(path==='/api/notifications'&&m==='DELETE'){
    need();await q(env,'delete from notifications where user_id=?',me.id).run();return J({ok:true});
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
  let apkUrl=env.HEXSTORE_APK_URL||'';
  if(!apkUrl){
    const hx=await q(env,"select v.apk_key from versions v join apps a on a.id=v.app_id where a.status='published' and v.status='approved' and v.apk_key<>'' and replace(replace(lower(a.name),' ',''),'-','')='hexstore' order by v.version_code desc limit 1").first();
    if(hx)apkUrl=base+'/files/'+hx.apk_key+'?dl=1';
  }
  const hexApkUrl=apkUrl||(base+'/?app='+encodeURIComponent(id));
  const webFallback=base+'/?app='+encodeURIComponent(id);
  const intentUrl='intent://hexstore/app/'+encodeURIComponent(id)+'#Intent;scheme=hexstore;package='+PACKAGE_NAME+';S.browser_fallback_url='+encodeURIComponent(webFallback)+';end';

  const html='<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>'+esc(a.name)+' — HEXSTORE</title><meta name="description" content="'+desc+'"><meta property="og:title" content="'+esc(a.name)+' — on HEXSTORE"><meta property="og:description" content="'+desc+'"><meta property="og:url" content="'+base+'/a/'+esc(id)+'">'+(icon?'<meta property="og:image" content="'+esc(icon)+'">':'')+'<meta name="twitter:card" content="summary_large_image"><meta name="theme-color" content="#35a64c"><style>*{box-sizing:border-box}body{margin:0;background:#0a0a0c;color:#f4f4f5;font:16px/1.5 system-ui,sans-serif}main{max-width:560px;margin:auto;padding:32px 18px 60px}.top{display:flex;align-items:center;gap:10px;color:#9a9aa4;font-weight:700;margin-bottom:26px}.top i{width:32px;height:32px;border-radius:10px;background:linear-gradient(135deg,#43c25c,#27913f);display:inline-block}.card{background:#17171b;border:1px solid #2b2b31;border-radius:24px;padding:26px}.ic{width:112px;height:112px;border-radius:26px;object-fit:cover;background:#222227;display:block}h1{font-size:32px;margin:20px 0 4px}.mu{color:#9a9aa4}.btn{display:flex;align-items:center;justify-content:center;text-align:center;background:linear-gradient(135deg,#43c25c,#27913f);color:#fff;text-decoration:none;font-weight:700;border-radius:14px;padding:16px 20px;font-size:17px;box-shadow:0 6px 20px #43c25c33}.btn.o{background:transparent;color:#f4f4f5;border:1px solid #2b2b31;box-shadow:none;margin-top:12px;font-weight:600}.st{display:grid;grid-template-columns:repeat(3,1fr);border-top:1px solid #2b2b31;margin:24px -26px 0;padding-top:16px;text-align:center;font-size:12px;color:#9a9aa4;text-transform:uppercase}.st b{display:block;font-size:20px;color:#f4f4f5;text-transform:none}h2{font-size:20px;margin:30px 0 8px}p{margin:0 0 10px;white-space:pre-wrap}.and-banner{position:fixed;top:10px;left:12px;right:12px;max-width:540px;margin:auto;z-index:100;background:#111216;border:1px solid #245a33;border-radius:20px;padding:12px 14px;box-shadow:0 12px 35px #000c;display:flex;align-items:center;gap:12px}.and-banner .ico{width:42px;height:42px;border-radius:12px;background:linear-gradient(135deg,#43c25c,#27913f);color:#fff;display:grid;place-items:center;font-size:22px;flex:none}.and-banner .tx{flex:1;min-width:0}.and-banner b{display:block;font-size:15px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.and-banner small{color:#9a9aa4;font-size:13px;display:block}.and-banner .b-inst{background:linear-gradient(135deg,#43c25c,#27913f);color:#fff;border:0;border-radius:10px;padding:8px 14px;font-weight:700;font-size:13px;text-decoration:none}.and-banner .b-cls{background:none;border:0;color:#f4f4f5;font-size:18px;padding:4px;cursor:pointer}</style></head><body>'+(apkUrl?'<div class="and-banner" id="ab"><div class="ico">📦</div><div class="tx"><b>Install HEXSTORE</b><small>Get the official app to download</small></div><a class="b-inst" href="'+esc(apkUrl)+'" download="HEXSTORE.apk">Install</a><button class="b-cls" onclick="document.getElementById(\'ab\').style.display=\'none\'">✕</button></div>':'')+'<main style="padding-top:'+(apkUrl?'70':'32')+'px"><div class="top"><i></i>HEXSTORE</div><div class="card">'+(icon?'<img class="ic" src="'+esc(icon)+'" alt="">':'<div class="ic"></div>')+'<h1>'+esc(a.name)+'</h1>'+(a.summary?'<p style="font-size:17px;margin:0 0 8px">'+esc(a.summary)+'</p>':'')+'<p class="mu">by '+esc(a.owner_name)+' · '+esc(a.category)+(a.price_mode&&a.price_mode!=='free'?' · '+esc(priceLabel(a)):'')+'</p><div style="margin-top:22px"><a class="btn" href="'+esc(hexApkUrl)+'"'+(apkUrl?' download="HEXSTORE.apk"':'')+'>'+(apkUrl?'Install HEXSTORE to view this app':'Open HEXSTORE')+'</a><a class="btn o" href="'+esc(intentUrl)+'">Already installed? Open in HEXSTORE</a>'+(apkUrl?'<p style="text-align:center;margin:16px 0 0"><a href="'+esc(webFallback)+'" style="color:#9a9aa4;text-decoration:underline">Not now, continue in browser</a></p>':'')+'</div><div class="st"><div><b>'+(a.rating||'–')+'</b>Rating</div><div><b>'+a.downloads+'</b>Downloads</div><div><b>'+(v?fsize(v.size):'–')+'</b>Size</div></div></div>'+(v?'<h2>What’s new in v'+esc(v.version_name)+'</h2><p>'+esc(v.changelog||'Initial release')+'</p>':'')+'<h2>About this app</h2><p>'+esc(a.description)+'</p></main></body></html>';
  return new Response(html,{headers:{'Content-Type':'text/html;charset=utf-8','Cache-Control':'public, max-age=300'}});
}
function fsize(b){b=+b||0;return b>=1048576?(b/1048576).toFixed(1)+' MB':Math.max(1,Math.round(b/1024))+' KB'}
