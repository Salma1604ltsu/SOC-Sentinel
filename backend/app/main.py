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

HTML = """<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>SOC Sentinel</title>
<style>
body{margin:0;background:#07111f;color:#e9f1fb;font-family:Inter,system-ui,sans-serif}header{padding:18px 28px;border-bottom:1px solid #1b3048;display:flex;justify-content:space-between}main{max-width:1200px;margin:auto;padding:28px}.brand{font-weight:900;color:#5ee7ff;letter-spacing:2px}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.card{background:#0d1a2b;border:1px solid #203852;border-radius:14px;padding:20px}.metric{font-size:32px;font-weight:900}.danger{color:#ff6b7a}button{background:#5ee7ff;border:0;border-radius:8px;padding:10px 14px;font-weight:800;cursor:pointer}input{background:#081524;color:white;border:1px solid #28455f;border-radius:8px;padding:11px;width:100%;box-sizing:border-box}table{width:100%;border-collapse:collapse;margin-top:18px}th,td{text-align:left;padding:12px;border-bottom:1px solid #203852;font-size:13px}.login{max-width:420px;margin:12vh auto;background:#0d1a2b;padding:32px;border-radius:18px;border:1px solid #203852}.hidden{display:none}.row{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px}.muted{color:#8ea3bb}@media(max-width:800px){.grid{grid-template-columns:1fr 1fr}.row{grid-template-columns:1fr}}
</style></head><body><header><div class='brand'>SOC SENTINEL</div><button onclick='logout()'>Logout</button></header>
<div id='login' class='login'><h1>AI-Assisted SOC</h1><p class='muted'>Defensive security monitoring and alert triage.</p><form onsubmit='login(event)'><p><input id='email' value='analyst@soc.local'></p><p><input id='password' type='password' value='ChangeMe123!'></p><button>Sign in</button><p id='err' class='danger'></p></form></div>
<main id='app' class='hidden'><h1>Security Operations Dashboard</h1><div class='grid'><div class='card'>Events<div id='events' class='metric'>0</div></div><div class='card'>Open Alerts<div id='open' class='metric'>0</div></div><div class='card'>Critical<div id='critical' class='metric danger'>0</div></div><div class='card'>High<div id='high' class='metric'>0</div></div></div>
<div class='card' style='margin-top:18px'><h2>Ingest Security Event</h2><form onsubmit='sendEvent(event)'><div class='row'><input id='ip' placeholder='Source IP' value='192.0.2.10'><input id='type' placeholder='Event type' value='authentication'></div><div class='row'><input id='status' placeholder='Status' value='failed'><input id='action' placeholder='Action' value='login'></div><p><input id='message' placeholder='Message'></p><button>Analyze Event</button></form></div>
<div class='card' style='margin-top:18px'><h2>Alert Queue</h2><table><thead><tr><th>Severity</th><th>Category</th><th>Title</th><th>Source</th><th>Status</th><th>Action</th></tr></thead><tbody id='alerts'></tbody></table></div></main>
<script>
let tok=localStorage.getItem('soc_token');const $=id=>document.getElementById(id);
async function api(u,o={}){o.headers={...(o.headers||{}),Authorization:'Bearer '+tok,'Content-Type':'application/json'};let r=await fetch(u,o);let d=await r.json();if(!r.ok)throw Error(d.detail||'Request failed');return d}
function show(){ $('login').classList.add('hidden');$('app').classList.remove('hidden');refresh()}
async function login(e){e.preventDefault();try{let r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:$('email').value,password:$('password').value})});let d=await r.json();if(!r.ok)throw Error(d.detail);tok=d.access_token;localStorage.setItem('soc_token',tok);show()}catch(x){$('err').textContent=x.message}}
function logout(){localStorage.removeItem('soc_token');location.reload()}
async function refresh(){try{let d=await api('/api/dashboard');$('events').textContent=d.events;$('open').textContent=d.open_alerts;$('critical').textContent=d.critical;$('high').textContent=d.high;let a=await api('/api/alerts');$('alerts').innerHTML=a.map(x=>`<tr><td>${x.severity}</td><td>${x.category}</td><td>${x.title}</td><td>${x.source_ip}</td><td>${x.status}</td><td><button onclick="closeAlert(${x.id})">Resolve</button></td></tr>`).join('')}catch(e){localStorage.removeItem('soc_token');location.reload()}}
async function closeAlert(id){await api('/api/alerts/'+id+'/status',{method:'POST',body:JSON.stringify({status:'resolved'})});refresh()}
async function sendEvent(e){e.preventDefault();let d=await api('/api/events',{method:'POST',body:JSON.stringify({source_ip:$('ip').value,event_type:$('type').value,status:$('status').value,action:$('action').value,message:$('message').value})});alert(d.detected?'Threat detected and alert created.':'Event ingested.');refresh()}
if(tok)show();
</script></body></html>"""
