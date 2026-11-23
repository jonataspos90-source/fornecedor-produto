'use strict';
const http=require('node:http'),fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto'),{Pool}=require('pg');
const PORT=Number(process.env.PORT||3000);
const ADMIN_EMAIL=(process.env.ADMIN_EMAIL||'').trim().toLowerCase();
const ADMIN_PASSWORD=process.env.ADMIN_PASSWORD||'';
if(!process.env.DATABASE_URL||!ADMIN_EMAIL||ADMIN_PASSWORD.length<12)throw Error('Configure DATABASE_URL, ADMIN_EMAIL e ADMIN_PASSWORD (12+ caracteres).');
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSLMODE==='require'?{rejectUnauthorized:false}:undefined});
const hash=(p,s=crypto.randomBytes(16).toString('hex'))=>s+':'+crypto.scryptSync(p,s,64).toString('hex');
function valid(p,h){const [s,v]=String(h||'').split(':');if(!s||!v||v.length!==128)return false;return crypto.timingSafeEqual(crypto.scryptSync(p,s,64),Buffer.from(v,'hex'))}
const sha=v=>crypto.createHash('sha256').update(v).digest('hex');
const json=(res,status,data)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(data))};
const redirect=(res,p)=>{res.writeHead(302,{Location:p,'Cache-Control':'no-store'});res.end()};
const cookie=(v,age)=>'fp_session='+encodeURIComponent(v)+'; HttpOnly; SameSite=Lax; Path=/; Max-Age='+age+(process.env.NODE_ENV==='production'?'; Secure':'');
const getCookie=req=>(req.headers.cookie||'').split(';').map(s=>s.trim()).find(s=>s.startsWith('fp_session='))?.slice(11)||'';
const sameOrigin=req=>{const o=req.headers.origin,h=req.headers.host;return !!o&&(o==='https://'+h||(process.env.NODE_ENV!=='production'&&o==='http://'+h))};
async function body(req){let s='';for await(const c of req){s+=c;if(s.length>16000)throw Error('Dados excedem o limite')}try{return JSON.parse(s||'{}')}catch{throw Error('JSON inválido')}}
async function userFrom(req){const t=getCookie(req);if(!t||t.length>256)return null;const q=await pool.query('SELECT u.id,u.email,u.display_name,u.role,s.token_hash FROM fp_sessions s JOIN fp_users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>NOW() AND u.active=true',[sha(t)]);return q.rows[0]||null}
async function serve(res,file,type){const b=await fs.readFile(path.join(__dirname,'public',file));res.writeHead(200,{'Content-Type':type,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(b)}
async function init(){
 await pool.query("CREATE TABLE IF NOT EXISTS fp_users(id UUID PRIMARY KEY,email TEXT NOT NULL UNIQUE,display_name TEXT NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('admin','user')),active BOOLEAN NOT NULL DEFAULT TRUE,created_at TIMESTAMPTZ DEFAULT NOW())");
 await pool.query("CREATE TABLE IF NOT EXISTS fp_sessions(token_hash TEXT PRIMARY KEY,user_id UUID NOT NULL REFERENCES fp_users(id) ON DELETE CASCADE,expires_at TIMESTAMPTZ NOT NULL)");
 const r=await pool.query('SELECT id FROM fp_users WHERE email=$1',[ADMIN_EMAIL]);
 if(!r.rowCount)await pool.query("INSERT INTO fp_users(id,email,display_name,password_hash,role) VALUES($1,$2,$3,$4,'admin')",[crypto.randomUUID(),ADMIN_EMAIL,'Administrador',hash(ADMIN_PASSWORD)]);
 await pool.query('DELETE FROM fp_sessions WHERE expires_at<NOW()');
}
const attempts=new Map();function allow(k){const now=Date.now();let x=attempts.get(k);if(!x||now-x.t>900000)x={t:now,n:0};x.n++;attempts.set(k,x);if(attempts.size>5000)attempts.clear();return x.n<=8}
const handler=async(req,res)=>{
 res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Content-Security-Policy',"frame-ancestors 'none'; base-uri 'self'; object-src 'none'");
 const p=(req.url||'/').split('?')[0];
 try{
  if(req.method==='GET'&&p==='/health')return json(res,200,{ok:true});
  if(req.method==='GET'&&p==='/login')return serve(res,'login.html','text/html; charset=utf-8');
  if(req.method==='GET'&&p==='/login.css')return serve(res,'login.css','text/css; charset=utf-8');
  if(req.method==='GET'&&p==='/login.js')return serve(res,'login.js','text/javascript; charset=utf-8');
  if(req.method==='POST'&&p==='/api/login'){
   if(!sameOrigin(req))return json(res,403,{error:'Origem inválida'});
   const b=await body(req),email=String(b.email||'').trim().toLowerCase(),pw=String(b.password||'');
   if(!allow(req.socket.remoteAddress+':'+email))return json(res,429,{error:'Muitas tentativas. Tente mais tarde.'});
   const r=await pool.query('SELECT * FROM fp_users WHERE email=$1 AND active=true',[email]);
   if(!r.rowCount||!valid(pw,r.rows[0].password_hash))return json(res,401,{error:'E-mail ou senha incorretos'});
   const token=crypto.randomBytes(32).toString('hex');
   await pool.query("INSERT INTO fp_sessions(token_hash,user_id,expires_at) VALUES($1,$2,NOW()+INTERVAL '7 days')",[sha(token),r.rows[0].id]);
   res.setHeader('Set-Cookie',cookie(token,604800));return json(res,200,{ok:true});
  }
  const u=await userFrom(req);
  if(req.method==='GET'&&p==='/api/me')return u?json(res,200,{email:u.email,name:u.display_name,role:u.role}):json(res,401,{error:'Não autenticado'});
  if(req.method==='POST'&&p==='/api/logout'){
   if(!sameOrigin(req))return json(res,403,{error:'Origem inválida'});
   if(u)await pool.query('DELETE FROM fp_sessions WHERE token_hash=$1',[u.token_hash]);
   res.setHeader('Set-Cookie',cookie('',0));return json(res,200,{ok:true});
  }
  if(!u){if(req.method==='GET')return redirect(res,'/login');return json(res,401,{error:'Acesso negado'})}
  if(req.method==='GET'&&(p==='/'||p==='/app'))return serve(res,'app.html','text/html; charset=utf-8');
  if(req.method==='GET'&&p==='/admin'&&u.role==='admin')return serve(res,'admin.html','text/html; charset=utf-8');
  if(req.method==='GET'&&p==='/admin.js'&&u.role==='admin')return serve(res,'admin.js','text/javascript; charset=utf-8');
  if(p.startsWith('/api/admin/')){
   if(u.role!=='admin')return json(res,403,{error:'Acesso restrito ao administrador'});
   if(req.method==='GET'&&p==='/api/admin/users'){
    const q=await pool.query('SELECT id,email,display_name,role,active,created_at FROM fp_users ORDER BY created_at');
    return json(res,200,{users:q.rows});
   }
   if(req.method==='POST'&&!sameOrigin(req))return json(res,403,{error:'Origem inválida'});
   if(req.method==='POST'&&p==='/api/admin/users'){
    const b=await body(req),email=String(b.email||'').trim().toLowerCase(),name=String(b.name||'').trim(),pw=String(b.password||''),role=b.role==='admin'?'admin':'user';
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||!name||pw.length<12)return json(res,400,{error:'Informe nome, e-mail válido e senha de 12+ caracteres'});
    await pool.query('INSERT INTO fp_users(id,email,display_name,password_hash,role) VALUES($1,$2,$3,$4,$5)',[crypto.randomUUID(),email,name,hash(pw),role]);
    return json(res,201,{ok:true});
   }
   const m=p.match(/^\/api\/admin\/users\/([0-9a-f-]{36})\/(toggle|password)$/);
   if(req.method==='POST'&&m){
    const id=m[1],b=await body(req);
    if(m[2]==='toggle'){
     if(id===u.id)return json(res,400,{error:'Não é possível bloquear a própria conta'});
     await pool.query('UPDATE fp_users SET active=NOT active WHERE id=$1',[id]);
     await pool.query('DELETE FROM fp_sessions WHERE user_id=$1',[id]);
    }else{
     if(String(b.password||'').length<12)return json(res,400,{error:'Senha precisa ter pelo menos 12 caracteres'});
     await pool.query('UPDATE fp_users SET password_hash=$1 WHERE id=$2',[hash(b.password),id]);
     await pool.query('DELETE FROM fp_sessions WHERE user_id=$1',[id]);
    }
    return json(res,200,{ok:true});
   }
  }
  return json(res,404,{error:'Página não encontrada'});
 }catch(e){console.error(e);return json(res,500,{error:e.code==='23505'?'E-mail já cadastrado':'Erro ao processar solicitação'})}
};
init().then(()=>http.createServer(handler).listen(PORT,'0.0.0.0',()=>console.log('Fornecedor Produto: porta '+PORT))).catch(e=>{console.error(e);process.exit(1)});
