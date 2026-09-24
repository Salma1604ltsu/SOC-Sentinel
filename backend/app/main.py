import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, func
from sqlalchemy.orm import declarative_base, sessionmaker, Session

BASE_DIR = Path(__file__).resolve().parent
DB_URL = os.getenv("DATABASE_URL", "sqlite:///./soc_sentinel.db")
if DB_URL.startswith("sqlite"):
    engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DB_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()
SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-me")
ALGORITHM = "HS256"
pwd = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(160), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(30), default="analyst")

class Event(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True)
    source_ip = Column(String(64), nullable=False)
    event_type = Column(String(80), nullable=False)
    action = Column(String(80), default="unknown")
    status = Column(String(40), default="unknown")
    message = Column(Text, default="")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    severity = Column(String(20), nullable=False)
    category = Column(String(80), nullable=False)
    title = Column(String(200), nullable=False)
    source_ip = Column(String(64), nullable=False)
    status = Column(String(30), default="open")
    evidence = Column(Text, default="")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

Base.metadata.create_all(engine)

app = FastAPI(title="SOC Sentinel", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])

class Login(BaseModel):
    email: str
    password: str

class EventIn(BaseModel):
    source_ip: str
    event_type: str
    action: str = "unknown"
    status: str = "unknown"
    message: str = ""

class AlertStatus(BaseModel):
    status: str

def db():
    s=SessionLocal()
    try: yield s
    finally: s.close()

def seed(s: Session):
    if not s.query(User).filter_by(email="analyst@soc.local").first():
        s.add(User(email="analyst@soc.local", password_hash=pwd.hash("ChangeMe123!"), role="analyst"))
        s.commit()

def token(user: User):
    exp=datetime.now(timezone.utc)+timedelta(minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES","60")))
    return jwt.encode({"sub":str(user.id),"email":user.email,"role":user.role,"exp":exp}, SECRET_KEY, algorithm=ALGORITHM)

def current_user(request: Request, s: Session=Depends(db)):
    h=request.headers.get("authorization","")
    if not h.startswith("Bearer "):
        raise HTTPException(401,"Authentication required")
    try:
        p=jwt.decode(h[7:],SECRET_KEY,algorithms=[ALGORITHM])
        u=s.get(User,int(p["sub"]))
        if not u: raise HTTPException(401,"Invalid token")
        return u
    except (JWTError, ValueError, KeyError):
        raise HTTPException(401,"Invalid token")

def detect(e: EventIn, s: Session):
    msg=(e.message+" "+e.action+" "+e.event_type).lower()
    severity=None; category=None; title=None
    if any(x in msg for x in ["union select","<script","../","etc/passwd","xp_cmdshell"]):
        severity,category,title="critical","web_attack","Suspicious web attack pattern"
    elif any(x in msg for x in ["nmap","masscan","port scan","syn scan"]):
        severity,category,title="medium","reconnaissance","Port scan indicator detected"
    elif any(x in msg for x in ["sudo","admin privilege","privilege escalation","setuid"]):
        severity,category,title="high","privilege_escalation","Privilege escalation indicator"
    elif e.status.lower()=="failed":
        recent=s.query(Event).filter(Event.source_ip==e.source_ip, Event.status=="failed").order_by(Event.created_at.desc()).limit(4).count()
        if recent>=4:
            severity,category,title="high","authentication","Possible brute-force activity"
    if severity:
        a=Alert(severity=severity,category=category,title=title,source_ip=e.source_ip,status="open",evidence=e.message or e.action)
        s.add(a); s.commit()
        return a

@app.on_event("startup")
def startup():
    s=SessionLocal()
    seed(s)
    s.close()

@app.get("/health")
def health(): return {"status":"ok","service":"SOC Sentinel"}

@app.get("/", response_class=HTMLResponse)
def home():
    return HTML

@app.post("/api/auth/login")
def login(data: Login, s: Session=Depends(db)):
    u=s.query(User).filter_by(email=data.email).first()
    if not u or not pwd.verify(data.password,u.password_hash):
        raise HTTPException(401,"Invalid email or password")
    return {"access_token":token(u),"user":{"email":u.email,"role":u.role}}

@app.get("/api/dashboard")
def dashboard(_: User=Depends(current_user), s: Session=Depends(db)):
    return {
      "events":s.query(Event).count(),
      "open_alerts":s.query(Alert).filter(Alert.status=="open").count(),
      "critical":s.query(Alert).filter(Alert.severity=="critical",Alert.status=="open").count(),
      "high":s.query(Alert).filter(Alert.severity=="high",Alert.status=="open").count()
    }

@app.get("/api/alerts")
def alerts(_: User=Depends(current_user), s: Session=Depends(db)):
    rows=s.query(Alert).order_by(Alert.id.desc()).limit(100).all()
    return [{"id":a.id,"severity":a.severity,"category":a.category,"title":a.title,"source_ip":a.source_ip,"status":a.status,"evidence":a.evidence,"created_at":a.created_at.isoformat()} for a in rows]

@app.post("/api/alerts/{alert_id}/status")
def alert_status(alert_id:int, data:AlertStatus, _:User=Depends(current_user), s:Session=Depends(db)):
    a=s.get(Alert,alert_id)
    if not a: raise HTTPException(404,"Alert not found")
    a.status=data.status; s.commit()
    return {"ok":True,"status":a.status}

@app.post("/api/events")
def create_event(data:EventIn, _:User=Depends(current_user), s:Session=Depends(db)):
    e=Event(**data.model_dump()); s.add(e); s.commit(); s.refresh(e)
    a=detect(data,s)
    return {"event_id":e.id,"alert_id":a.id if a else None,"detected":bool(a)}

@app.get("/api/events")
def events(_:User=Depends(current_user), s:Session=Depends(db)):
    rows=s.query(Event).order_by(Event.id.desc()).limit(100).all()
    return [{"id":e.id,"source_ip":e.source_ip,"event_type":e.event_type,"action":e.action,"status":e.status,"message":e.message,"created_at":e.created_at.isoformat()} for e in rows]

@app.get("/api/ip/{ip}")
def ip_intel(ip:str, _:User=Depends(current_user)):
    private=ip.startswith(("10.","192.168.","172.16.","127."))
    return {"ip":ip,"classification":"private/internal" if private else "external/unknown","reputation":"demo placeholder","note":"Connect a vetted threat-intelligence provider for production use."}

HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOC Sentinel | Security Operations Center</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:#050b14;color:#eaf2ff;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;overflow-x:hidden}
body:before{content:"";position:fixed;inset:0;background:radial-gradient(circle at 20% 20%,rgba(56,189,248,.13),transparent 32%),radial-gradient(circle at 85% 80%,rgba(99,102,241,.12),transparent 30%);pointer-events:none}
.topbar{height:68px;padding:0 34px;border-bottom:1px solid #17283b;background:rgba(5,11,20,.82);backdrop-filter:blur(14px);display:flex;align-items:center;justify-content:space-between;position:relative;z-index:2}
.brand{display:flex;align-items:center;gap:11px;font-weight:900;letter-spacing:1.8px}.shield{width:34px;height:34px;border-radius:10px;display:grid;place-items:center;background:linear-gradient(135deg,#22d3ee,#6366f1);color:#03101a;font-weight:1000}.brand span{color:#5ee7ff}
.top-status{font-size:12px;color:#86a0b9;display:flex;align-items:center;gap:8px}.dot{width:7px;height:7px;border-radius:50%;background:#35e58b;box-shadow:0 0 12px #35e58b}
.login-wrap{min-height:calc(100vh - 68px);display:grid;place-items:center;padding:42px 20px;position:relative;z-index:1}
.login-card{width:min(440px,100%);background:rgba(10,22,37,.88);border:1px solid #1d3852;border-radius:24px;padding:36px;box-shadow:0 30px 90px rgba(0,0,0,.42)}
.kicker{font-size:12px;letter-spacing:2px;text-transform:uppercase;color:#5ee7ff;font-weight:800;margin-bottom:10px}
h1{font-size:30px;margin:0 0 9px}.subtitle{color:#8fa6bd;line-height:1.6;margin:0 0 28px;font-size:14px}
.field{margin-bottom:17px}.field label{display:block;font-size:12px;color:#a9bbcd;font-weight:700;margin:0 0 8px}
.input-wrap{position:relative}.input-wrap input{padding-right:44px}
input{width:100%;background:#071321;color:#f4f8ff;border:1px solid #29445d;border-radius:11px;padding:13px 14px;outline:none;font-size:14px;transition:.2s}
input:focus{border-color:#36c9ef;box-shadow:0 0 0 3px rgba(54,201,239,.11)}
.toggle{position:absolute;right:8px;top:7px;border:0;background:transparent;color:#7791aa;padding:7px;cursor:pointer;font-size:12px}
.signin{width:100%;border:0;border-radius:11px;padding:13px;background:linear-gradient(135deg,#36d5f2,#6375ff);color:#04101a;font-weight:900;cursor:pointer;transition:.2s;box-shadow:0 8px 24px rgba(54,201,239,.18)}
.signin:hover{transform:translateY(-1px);filter:brightness(1.06)}
.err{min-height:18px;color:#ff7182;font-size:12px;margin:12px 0 0;text-align:center}
.demo{margin-top:20px;padding:14px;border:1px solid #20384f;background:#081522;border-radius:12px;font-size:12px;color:#8198ae;line-height:1.6}
.demo strong{color:#dce9f5}.demo button{margin-top:9px;width:100%;background:#102438;color:#9bdff0;border:1px solid #254c66;border-radius:9px;padding:9px;cursor:pointer;font-weight:700}

.cyber-bg{position:fixed;inset:0;overflow:hidden;pointer-events:none;z-index:0;background:#030913}
.cyber-grid{position:absolute;inset:-30%;background-image:linear-gradient(rgba(54,213,242,.075) 1px,transparent 1px),linear-gradient(90deg,rgba(99,117,255,.075) 1px,transparent 1px);background-size:55px 55px;transform:perspective(500px) rotateX(58deg) translateY(15%);transform-origin:center;animation:gridMove 16s linear infinite}
@keyframes gridMove{0%{transform:perspective(500px) rotateX(58deg) translateY(0)}100%{transform:perspective(500px) rotateX(58deg) translateY(55px)}}
.orb{position:absolute;border-radius:50%;filter:blur(1px);opacity:.38;animation:float 9s ease-in-out infinite}
.orb.one{width:280px;height:280px;left:8%;top:12%;background:radial-gradient(circle,rgba(34,211,238,.32),transparent 68%)}
.orb.two{width:360px;height:360px;right:4%;bottom:5%;background:radial-gradient(circle,rgba(99,102,241,.28),transparent 68%);animation-delay:-3s}
.orb.three{width:180px;height:180px;right:28%;top:10%;background:radial-gradient(circle,rgba(56,189,248,.18),transparent 68%);animation-delay:-6s}
@keyframes float{0%,100%{transform:translate3d(0,0,0) scale(1)}50%{transform:translate3d(0,-24px,0) scale(1.06)}}
.scanline{position:absolute;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,rgba(94,231,255,.35),transparent);box-shadow:0 0 18px rgba(94,231,255,.25);animation:scan 6s linear infinite}
@keyframes scan{0%{top:-5%}100%{top:105%}}
.particle{position:absolute;width:3px;height:3px;border-radius:50%;background:#62e7ff;box-shadow:0 0 10px #62e7ff;animation:drift linear infinite}
.p1{left:12%;top:70%;animation-duration:11s}.p2{left:27%;top:30%;animation-duration:14s;animation-delay:-4s}.p3{left:72%;top:65%;animation-duration:12s;animation-delay:-7s}.p4{left:86%;top:22%;animation-duration:15s;animation-delay:-2s}.p5{left:55%;top:80%;animation-duration:13s;animation-delay:-5s}
@keyframes drift{0%{transform:translateY(35px);opacity:0}20%{opacity:.8}80%{opacity:.8}100%{transform:translateY(-180px);opacity:0}}
.login-wrap{position:relative;z-index:1}
.login-card{background:rgba(6,17,30,.78);backdrop-filter:blur(18px);box-shadow:0 0 0 1px rgba(94,231,255,.08),0 30px 100px rgba(0,0,0,.55),0 0 55px rgba(54,213,242,.08)}
.cyber-tag{display:inline-flex;align-items:center;gap:7px;margin-bottom:16px;padding:6px 10px;border:1px solid #23485f;border-radius:999px;background:rgba(13,38,55,.65);color:#78eaff;font-size:10px;font-weight:800;letter-spacing:1.4px;text-transform:uppercase}
.cyber-tag i{width:6px;height:6px;border-radius:50%;background:#35e58b;box-shadow:0 0 10px #35e58b}
.security-lines{display:flex;gap:14px;margin-top:22px;color:#5e7891;font-size:10px;letter-spacing:.5px}.security-lines span{display:flex;align-items:center;gap:5px}.security-lines b{color:#36d5f2}
.secure{margin-top:18px;text-align:center;color:#5f7890;font-size:11px}
.hidden{display:none}
main{max-width:1200px;margin:auto;padding:30px;position:relative;z-index:1}
.dashboard-head{display:flex;align-items:end;justify-content:space-between;gap:15px;margin-bottom:22px}.dashboard-head h1{font-size:28px}.muted{color:#8ea3bb;font-size:13px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.card{background:#0b1929;border:1px solid #203852;border-radius:15px;padding:20px}.metric{font-size:32px;font-weight:900;margin-top:6px}.danger{color:#ff6b7a}
button{font-family:inherit}.logout{background:#102438;color:#b7cbe0;border:1px solid #29445d;border-radius:9px;padding:9px 14px;font-weight:700;cursor:pointer}
.row{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px}
.card input{background:#071321}.card button:not(.logout){background:#5ee7ff;border:0;border-radius:8px;padding:10px 14px;font-weight:800;cursor:pointer}
table{width:100%;border-collapse:collapse;margin-top:18px}th,td{text-align:left;padding:12px;border-bottom:1px solid #203852;font-size:13px}th{color:#7f97ad;font-size:11px;text-transform:uppercase;letter-spacing:.7px}
@media(max-width:800px){.grid{grid-template-columns:1fr 1fr}.row{grid-template-columns:1fr}.topbar{padding:0 18px}.login-card{padding:28px}main{padding:20px}}
@media(max-width:520px){.grid{grid-template-columns:1fr}.top-status{display:none}}
</style>
</head>
<body>
<header class="topbar">
  <div class="brand"><div class="shield">S</div><div>SOC <span>SENTINEL</span></div></div>
  <div class="top-status"><i class="dot"></i> SOC SYSTEM ONLINE</div>
</header>

<div class="cyber-bg" aria-hidden="true"><div class="cyber-grid"></div><div class="orb one"></div><div class="orb two"></div><div class="orb three"></div><div class="scanline"></div><i class="particle p1"></i><i class="particle p2"></i><i class="particle p3"></i><i class="particle p4"></i><i class="particle p5"></i></div><section id="login" class="login-wrap">
  <div class="login-card">
    <div class="cyber-tag"><i></i> Secure SOC Access</div><div class="kicker">Security Operations Center</div>
    <h1>Welcome back</h1>
    <p class="subtitle">Sign in to monitor security events, investigate alerts, and manage incident response.</p>
    <form onsubmit="login(event)">
      <div class="field">
        <label for="email">WORK EMAIL</label>
        <input id="email" type="email" autocomplete="username" placeholder="analyst@soc.local" required>
      </div>
      <div class="field">
        <label for="password">PASSWORD</label>
        <div class="input-wrap">
          <input id="password" type="password" autocomplete="current-password" placeholder="Enter your password" required>
          <button type="button" class="toggle" onclick="togglePassword()">SHOW</button>
        </div>
      </div>
      <button class="signin" type="submit">Sign in to SOC Sentinel</button>
      <div id="err" class="err"></div>
    </form>
    <div class="demo">
      <strong>Demo analyst account</strong><br>
      Use the preconfigured local analyst account for portfolio demonstrations.
      <button type="button" onclick="fillDemo()">Use demo credentials</button>
    </div>
    <div class="security-lines"><span>◉ <b>24/7</b> Monitoring</span><span>◉ <b>JWT</b> Protected</span></div><div class="secure">🔒 Authenticated access · SOC Sentinel</div>
  </div>
</section>

<header id="appbar" class="topbar hidden">
  <div class="brand"><div class="shield">S</div><div>SOC <span>SENTINEL</span></div></div>
  <button class="logout" onclick="logout()">Logout</button>
</header>

<main id="app" class="hidden">
  <div class="dashboard-head">
    <div><h1>Security Operations Dashboard</h1><div class="muted">AI-assisted event monitoring and alert triage</div></div>
  </div>
  <div class="grid">
    <div class="card">Events<div id="events" class="metric">0</div></div>
    <div class="card">Open Alerts<div id="open" class="metric">0</div></div>
    <div class="card">Critical<div id="critical" class="metric danger">0</div></div>
    <div class="card">High<div id="high" class="metric danger">0</div></div>
  </div>
  <div class="card" style="margin-top:18px">
    <h2>Ingest Security Event</h2>
    <form onsubmit="sendEvent(event)">
      <div class="row"><input id="ip" placeholder="Source IP" value="192.0.2.10"><input id="type" placeholder="Event type" value="authentication"></div>
      <div class="row"><input id="status" placeholder="Status" value="failed"><input id="action" placeholder="Action" value="login"></div>
      <p><input id="message" placeholder="Message"></p><button>Analyze Event</button>
    </form>
  </div>
  <div class="card" style="margin-top:18px"><h2>Alert Queue</h2><table><thead><tr><th>Severity</th><th>Category</th><th>Title</th><th>Source</th><th>Status</th><th>Action</th></tr></thead><tbody id="alerts"></tbody></table></div>
</main>

<script>
let tok=localStorage.getItem('soc_token');const $=id=>document.getElementById(id);
async function api(u,o={}){o.headers={...(o.headers||{}),Authorization:'Bearer '+tok,'Content-Type':'application/json'};let r=await fetch(u,o);let d=await r.json();if(!r.ok)throw Error(d.detail||'Request failed');return d}
function fillDemo(){$('email').value='analyst@soc.local';$('password').value='ChangeMe123!';$('password').focus()}
function togglePassword(){let p=$('password'),b=document.querySelector('.toggle');p.type=p.type==='password'?'text':'password';b.textContent=p.type==='password'?'SHOW':'HIDE'}
function show(){$('login').classList.add('hidden');$('appbar').classList.remove('hidden');$('app').classList.remove('hidden');refresh()}
async function login(e){e.preventDefault();$('err').textContent='';try{let r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:$('email').value,password:$('password').value})});let d=await r.json();if(!r.ok)throw Error(d.detail||'Invalid credentials');tok=d.access_token;localStorage.setItem('soc_token',tok);show()}catch(x){$('err').textContent=x.message}}
function logout(){localStorage.removeItem('soc_token');location.reload()}
async function refresh(){try{let d=await api('/api/dashboard');$('events').textContent=d.events;$('open').textContent=d.open_alerts;$('critical').textContent=d.critical;$('high').textContent=d.high;let a=await api('/api/alerts');$('alerts').innerHTML=a.map(x=>'<tr><td>'+x.severity+'</td><td>'+x.category+'</td><td>'+x.title+'</td><td>'+x.source_ip+'</td><td>'+x.status+'</td><td><button onclick="closeAlert('+x.id+')">Resolve</button></td></tr>').join('')}catch(e){localStorage.removeItem('soc_token');location.reload()}}
async function closeAlert(id){await api('/api/alerts/'+id+'/status',{method:'POST',body:JSON.stringify({status:'resolved'})});refresh()}
async function sendEvent(e){e.preventDefault();let d=await api('/api/events',{method:'POST',body:JSON.stringify({source_ip:$('ip').value,event_type:$('type').value,status:$('status').value,action:$('action').value,message:$('message').value})});alert(d.detected?'Threat detected and alert created.':'Event ingested.');refresh()}
if(tok)show();
</script>
</body>
</html>"""
