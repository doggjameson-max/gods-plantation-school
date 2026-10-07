const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 10000;
const ADMIN_KEY = process.env.ADMIN_KEY || 'change-this-school-key';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, {recursive:true});
const db = new Database(path.join(DATA_DIR, 'school.db'));
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS app_state (id INTEGER PRIMARY KEY CHECK(id=1), state TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT, actor TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('admin','teacher','parent')),
 name TEXT NOT NULL,
 link_id TEXT DEFAULT '',
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
 token TEXT PRIMARY KEY,
 user_id INTEGER NOT NULL,
 expires_at TEXT NOT NULL,
 created_at TEXT NOT NULL,
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

const defaultState = {
  students:[], parents:[], staff:[], classes:[], subjects:[], lessons:[], attendance:{}, results:[], fees:[], payments:[], announcements:[],
  website:{name:"God's Plantation School Ikirun",tagline:'Excellence, character and service.',phone:'',email:'',address:'Ikirun, Osun State, Nigeria',about:''},
  settings:{session:'2026/2027',term:'First Term',openingTime:'07:30',closingTime:'09:00'},
  permissions:{Administrator:true,Teacher:true,Accountant:true,Parent:true,Student:true},
  security:{confirmDelete:true,lockScreen:false,activityLog:true}, audit:[]
};
function getState(){const row=db.prepare('SELECT state FROM app_state WHERE id=1').get(); return row ? JSON.parse(row.state) : structuredClone(defaultState);}
function putState(state){const now=new Date().toISOString();db.prepare(`INSERT INTO app_state(id,state,updated_at) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state, updated_at=excluded.updated_at`).run(JSON.stringify(state),now);return now;}
if(!db.prepare('SELECT 1 FROM app_state WHERE id=1').get()) putState(defaultState);

function hashPassword(password){const salt=crypto.randomBytes(16).toString('hex');const hash=crypto.scryptSync(String(password),salt,64).toString('hex');return `${salt}:${hash}`;}
function verifyPassword(password,stored){try{const [salt,hash]=stored.split(':');const actual=crypto.scryptSync(String(password),salt,64);return crypto.timingSafeEqual(actual,Buffer.from(hash,'hex'));}catch{return false;}}
function makeToken(){return crypto.randomBytes(48).toString('hex');}
function cleanUser(u){return {id:u.id,username:u.username,role:u.role,name:u.name,linkId:u.link_id,active:!!u.active};}
function seedAdmin(){
  if(!db.prepare('SELECT 1 FROM users WHERE role="admin" LIMIT 1').get()){
    const password=process.env.ADMIN_INITIAL_PASSWORD || 'Admin@12345';
    db.prepare('INSERT INTO users(username,password_hash,role,name,created_at) VALUES(?,?,?,?,?)').run('admin',hashPassword(password),'admin','School Administrator',new Date().toISOString());
    console.log('Initial admin account: username=admin, password='+password+' (change it after login)');
  }
}
seedAdmin();

app.use(express.json({limit:'5mb'}));
app.use(express.static(path.join(__dirname,'public')));
function auth(req,res,next){
  const token=req.get('authorization')?.replace(/^Bearer\s+/i,'') || req.get('x-session-token');
  if(!token) return res.status(401).json({error:'Login required'});
  const row=db.prepare(`SELECT s.token,s.expires_at,u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND u.active=1`).get(token);
  if(!row || new Date(row.expires_at)<new Date()){if(row)db.prepare('DELETE FROM sessions WHERE token=?').run(token);return res.status(401).json({error:'Session expired'});}
  req.user=row;req.token=token;next();
}
function adminOnly(req,res,next){if(req.user.role!=='admin')return res.status(403).json({error:'Administrator access required'});next();}
function audit(action,actor){db.prepare('INSERT INTO audit_log(action,actor,created_at) VALUES(?,?,?)').run(action,actor,new Date().toISOString());}

app.get('/api/health',(req,res)=>res.json({ok:true,service:"God's Plantation School",time:new Date().toISOString()}));
app.post('/api/auth/login',(req,res)=>{
  const username=String(req.body?.username||'').trim().toLowerCase();const password=String(req.body?.password||'');
  const u=db.prepare('SELECT * FROM users WHERE lower(username)=? AND active=1').get(username);
  if(!u || !verifyPassword(password,u.password_hash)) return res.status(401).json({error:'Invalid username or password'});
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(new Date().toISOString());
  const token=makeToken(),now=new Date(),expires=new Date(now.getTime()+1000*60*60*24*7).toISOString();
  db.prepare('INSERT INTO sessions(token,user_id,expires_at,created_at) VALUES(?,?,?,?)').run(token,u.id,expires,now.toISOString());
  audit('User login: '+u.username,u.username);
  res.json({token,expiresAt:expires,user:cleanUser(u)});
});
app.post('/api/auth/logout',auth,(req,res)=>{db.prepare('DELETE FROM sessions WHERE token=?').run(req.token);audit('User logout: '+req.user.username,req.user.username);res.json({ok:true});});
app.get('/api/auth/me',auth,(req,res)=>res.json({user:cleanUser(req.user),expiresAt:req.user.expires_at}));
app.post('/api/auth/change-password',auth,(req,res)=>{
  const current=String(req.body?.currentPassword||''),next=String(req.body?.newPassword||'');
  if(next.length<8)return res.status(400).json({error:'New password must be at least 8 characters'});
  if(!verifyPassword(current,req.user.password_hash))return res.status(401).json({error:'Current password is incorrect'});
  db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(hashPassword(next),req.user.id);audit('Password changed',req.user.username);res.json({ok:true});
});

function filteredState(state,user){
  if(user.role==='admin') return state;
  const out=structuredClone(state);
  if(user.role==='teacher'){
    const staff=out.staff.find(x=>x.id===user.link_id);
    const allowedClasses=new Set(staff?.classes||[]);
    out.students=allowedClasses.size?out.students.filter(s=>allowedClasses.has(s.class)):out.students;
    out.parents=out.parents.filter(p=>out.students.some(s=>s.id===p.studentId));
    out.fees=[];out.payments=[];
    out.staff=staff?[staff]:[];
    out.permissions={Teacher:true};out.security={confirmDelete:true,lockScreen:false,activityLog:false};
  } else if(user.role==='parent'){
    const children=out.students.filter(s=>out.parents.some(p=>p.id===user.link_id&&p.studentId===s.id));
    const childIds=new Set(children.map(s=>s.id));
    out.students=children;out.parents=out.parents.filter(p=>p.id===user.link_id);out.staff=[];
    out.lessons=out.lessons.filter(l=>children.some(s=>s.class===l.class));
    out.results=out.results.filter(r=>childIds.has(r.studentId));
    out.fees=out.fees.filter(f=>!f.studentId||childIds.has(f.studentId));
    out.payments=out.payments.filter(p=>childIds.has(p.studentId));
    out.attendance=Object.fromEntries(Object.entries(out.attendance).map(([k,v])=>[k,Object.fromEntries(Object.entries(v).filter(([id])=>childIds.has(id))) ]));
    out.permissions={Parent:true};out.security={confirmDelete:false,lockScreen:false,activityLog:false};
  }
  return out;
}
app.get('/api/state',auth,(req,res)=>{const row=db.prepare('SELECT state,updated_at FROM app_state WHERE id=1').get();res.json({state:filteredState(JSON.parse(row.state),req.user),updatedAt:row.updated_at,user:cleanUser(req.user)});});

function mergeTeacher(current,incoming,user){
  const next=structuredClone(current);const staff=next.staff.find(x=>x.id===user.link_id);const classes=new Set(staff?.classes||[]);
  if(Array.isArray(incoming.lessons)){
    const incomingIds=new Set(incoming.lessons.map(x=>x.id));
    next.lessons=next.lessons.filter(l=>!incomingIds.has(l.id));
    next.lessons.push(...incoming.lessons.filter(l=>!l.teacherUserId||l.teacherUserId===user.link_id||classes.has(l.class)));
  }
  if(incoming.attendance && typeof incoming.attendance==='object'){
    for(const [key,rec] of Object.entries(incoming.attendance)){
      if(!next.attendance[key]) next.attendance[key]={};
      for(const [studentId,status] of Object.entries(rec)){
        const student=next.students.find(s=>s.id===studentId);
        if(student && (!classes.size || classes.has(student.class))) next.attendance[key][studentId]=status;
      }
    }
  }
  if(Array.isArray(incoming.results)){
    for(const r of incoming.results){
      const student=next.students.find(s=>s.id===r.studentId);
      if(!student || (classes.size && !classes.has(student.class))) continue;
      next.results=next.results.filter(x=>!(x.studentId===r.studentId&&x.term===r.term));next.results.push(r);
    }
  }
  if(staff){const updated=incoming.staff?.find?.(x=>x.id===user.link_id);if(updated)Object.assign(staff,updated);}
  return next;
}
app.put('/api/state',auth,(req,res)=>{
  if(!req.body || typeof req.body !== 'object') return res.status(400).json({error:'Invalid state'});
  let state;
  if(req.user.role==='admin') state=req.body;
  else if(req.user.role==='teacher') state=mergeTeacher(getState(),req.body,req.user);
  else return res.status(403).json({error:'Parents cannot modify school records'});
  const now=putState(state);audit('State synchronized',req.user.username);res.json({ok:true,updatedAt:now});
});

app.get('/api/users',auth,adminOnly,(req,res)=>res.json(db.prepare('SELECT id,username,role,name,link_id AS linkId,active,created_at AS createdAt FROM users ORDER BY id DESC').all()));
app.post('/api/users',auth,adminOnly,(req,res)=>{
  const username=String(req.body?.username||'').trim().toLowerCase(),password=String(req.body?.password||''),role=String(req.body?.role||''),name=String(req.body?.name||'').trim(),linkId=String(req.body?.linkId||'');
  if(!username||!name||password.length<8||!['teacher','parent'].includes(role))return res.status(400).json({error:'Provide username, name, teacher/parent role and a password of at least 8 characters'});
  if(db.prepare('SELECT 1 FROM users WHERE username=?').get(username))return res.status(409).json({error:'Username already exists'});
  if(role==='teacher'&&!db.prepare('SELECT 1 FROM users WHERE 1').get()){}
  try{const info=db.prepare('INSERT INTO users(username,password_hash,role,name,link_id,created_at) VALUES(?,?,?,?,?,?)').run(username,hashPassword(password),role,name,linkId,new Date().toISOString());audit('Created '+role+' account: '+username,req.user.username);res.json({ok:true,id:info.lastInsertRowid});}catch(e){res.status(500).json({error:'Unable to create account'});}
});
app.patch('/api/users/:id',auth,adminOnly,(req,res)=>{const id=Number(req.params.id);const active=req.body?.active?1:0;db.prepare('UPDATE users SET active=? WHERE id=?').run(active,id);audit((active?'Activated':'Deactivated')+' user '+id,req.user.username);res.json({ok:true});});
app.delete('/api/users/:id',auth,adminOnly,(req,res)=>{const id=Number(req.params.id);const u=db.prepare('SELECT * FROM users WHERE id=?').get(id);if(!u||u.role==='admin')return res.status(400).json({error:'Administrator account cannot be deleted here'});db.prepare('DELETE FROM users WHERE id=?').run(id);audit('Deleted user '+id,req.user.username);res.json({ok:true});});
app.get('/api/audit',auth,adminOnly,(req,res)=>res.json(db.prepare('SELECT action,actor,created_at FROM audit_log ORDER BY id DESC LIMIT 200').all()));

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT,()=>console.log(`God's Plantation School running on ${PORT}`));
