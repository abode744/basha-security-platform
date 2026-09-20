import os
from pathlib import Path
from fastapi import FastAPI,Depends,HTTPException,Header,WebSocket,WebSocketDisconnect
from fastapi.responses import FileResponse,Response
from pydantic import BaseModel,Field
from sqlalchemy import select,func
from sqlalchemy.orm import Session
from .db import Base,engine,get_db,SessionLocal
from .models import *
from .security import verify_password,make_token,decode_token
from .scope import validate
from .worker import run_scan
from .tools import available,TOOL_DEFS,tool_modes
Base.metadata.create_all(engine)
try:
    from . import bootstrap
except Exception:
    pass
app=FastAPI(title='BASHA',version='1.0.0')
class Login(BaseModel):username:str;password:str
class NewScan(BaseModel):
 root:str;include:list[str]=Field(default_factory=list);exclude:list[str]=Field(default_factory=list);excluded_paths:list[str]=Field(default_factory=list);max_rps:float=Field(1,ge=.1,le=5);concurrency:int=Field(1,ge=1,le=4);stage_cooldown:int=Field(240,ge=0,le=3600);profile:str='safe';authorization_confirmed:bool

def auth(h,db):
 if not h or not h.startswith('Bearer '):raise HTTPException(401,'Authentication required')
 p=decode_token(h[7:]);
 if not p:raise HTTPException(401,'Invalid token')
 u=db.execute(select(User).where(User.username==p.get('sub'),User.disabled==False)).scalar_one_or_none()
 if not u:raise HTTPException(401,'Invalid user')
 return u
def _find_static():
    for c in [
        Path(__file__).resolve().parent.parent / 'static' / 'index.html',
        Path('static/index.html'),
        Path('/var/task/static/index.html'),
        Path('/app/static/index.html')
    ]:
        if c.exists(): return c
    return Path(__file__).resolve().parent.parent / 'static' / 'index.html'
STATIC_INDEX = _find_static()
@app.get('/')
def home():return FileResponse(STATIC_INDEX)
@app.get('/api/health')
def health():
 db=SessionLocal()
 try:db.execute(select(func.count(User.id))).scalar();return {'status':'ok','tools':available(),'modes':tool_modes()}
 finally:db.close()
@app.post('/api/login')
def login(x:Login,db:Session=Depends(get_db)):
 u=db.execute(select(User).where(User.username==x.username)).scalar_one_or_none()
 if not u or u.disabled or not verify_password(x.password,u.password_hash):raise HTTPException(401,'Invalid credentials')
 db.add(AuditLog(username=u.username,action='login'));db.commit();return {'token':make_token(u.username)}
@app.get('/api/dashboard')
def dashboard(authorization:str|None=Header(None),db:Session=Depends(get_db)):
 auth(authorization,db);qs={'targets':select(func.count(Target.id)),'scans':select(func.count(Scan.id)),'active_scans':select(func.count(Scan.id)).where(Scan.status.in_(['QUEUED','RUNNING','PAUSED'])),'assets':select(func.count(Asset.id)),'live_hosts':select(func.count(Asset.id)).where(Asset.status=='LIVE'),'urls':select(func.count(URL.id)),'endpoints':select(func.count(Endpoint.id)),'technologies':select(func.count(Technology.id)),'findings':select(func.count(Finding.id)),'high_confidence':select(func.count(Finding.id)).where(Finding.confidence=='HIGH'),'errors':select(func.count(ToolRun.id)).where(ToolRun.status.in_(['FAILED','TIMEOUT']))};return {k:db.scalar(q) or 0 for k,q in qs.items()}
@app.get('/api/tools')
def tools(authorization:str|None=Header(None),db:Session=Depends(get_db)):auth(authorization,db);return {'available':available(),'definitions':TOOL_DEFS,'modes':tool_modes()}
@app.post('/api/scans')
def create(x:NewScan,authorization:str|None=Header(None),db:Session=Depends(get_db)):
 u=auth(authorization,db)
 if not x.authorization_confirmed:raise HTTPException(400,'Authorization confirmation is required')
 if x.profile not in {'passive','safe','extended'}:raise HTTPException(400,'Invalid profile')
 try:root,inc,exc=validate(x.root,x.include,x.exclude)
 except ValueError as e:raise HTTPException(400,str(e))
 t=db.execute(select(Target).where(Target.root==root)).scalar_one_or_none()
 if not t:t=Target(root=root);db.add(t);db.commit();db.refresh(t)
 if not t.enabled:raise HTTPException(400,'Target is disabled')
 sc=Scope(target_id=t.id,include='\n'.join(inc),exclude='\n'.join(exc),excluded_paths='\n'.join(x.excluded_paths),max_rps=x.max_rps,concurrency=x.concurrency,stage_cooldown=x.stage_cooldown,profile=x.profile,authorization_confirmed=True);db.add(sc);db.commit();db.refresh(sc)
 s=Scan(target_id=t.id,scope_id=sc.id,profile=x.profile);db.add(s);db.commit();db.refresh(s)
 use_celery = os.getenv('USE_CELERY', '0') == '1'
 if use_celery:
     try:
         run_scan.delay(s.id)
     except Exception:
         from .local_worker import start_local_scan_thread
         start_local_scan_thread(s.id)
 else:
     from .local_worker import start_local_scan_thread
     start_local_scan_thread(s.id)
 db.add(AuditLog(username=u.username,action='create_scan',details=f'{root} scan={s.id}'));db.commit();return {'id':s.id}
@app.get('/api/scans')
def scans(authorization:str|None=Header(None),db:Session=Depends(get_db)):
 auth(authorization,db);return [{'id':s.id,'status':s.status,'progress':s.progress,'stage':s.current_stage,'tool':s.current_tool,'created_at':s.created_at} for s in db.execute(select(Scan).order_by(Scan.id.desc()).limit(100)).scalars()]
@app.get('/api/scans/{sid}')
def detail(sid:int,authorization:str|None=Header(None),db:Session=Depends(get_db)):
 auth(authorization,db);s=db.get(Scan,sid)
 if not s:raise HTTPException(404,'Not found')
 return {'scan':{'id':s.id,'status':s.status,'progress':s.progress,'stage':s.current_stage,'tool':s.current_tool,'profile':s.profile},'assets':[{'hostname':a.hostname,'status':a.status,'source':a.source} for a in db.execute(select(Asset).where(Asset.scan_id==sid)).scalars()],'findings':[{'id':f.id,'title':f.title,'severity':f.severity,'url':f.url,'verification':f.verification,'confidence':f.confidence,'source':f.source,'evidence':f.evidence} for f in db.execute(select(Finding).where(Finding.scan_id==sid)).scalars()],'logs':[{'level':l.level,'message':l.message,'created_at':l.created_at} for l in db.execute(select(Log).where(Log.scan_id==sid).order_by(Log.id.desc()).limit(500)).scalars()]}
for action,field in [('pause','pause_requested'),('resume','pause_requested'),('stop','cancel_requested')]:
 def make(a,f):
  def endpoint(sid:int,authorization:str|None=Header(None),db:Session=Depends(get_db)):
   auth(authorization,db);s=db.get(Scan,sid)
   if not s:raise HTTPException(404,'Not found')
   setattr(s,f,False if a=='resume' else True);db.commit();return {'status':a.upper()+'_REQUESTED'}
  return endpoint
 app.add_api_route('/api/scans/{sid}/'+action,make(action,field),methods=['POST'])
@app.get('/api/schedules')
def schedules(authorization:str|None=Header(None),db:Session=Depends(get_db)):
 auth(authorization,db);return [{k:v for k,v in x.__dict__.items() if k!='_sa_instance_state'} for x in db.execute(select(Schedule).order_by(Schedule.id.desc())).scalars()]
class ScheduleIn(BaseModel):
 target_id:int;scope_id:int;frequency_minutes:int=Field(1440,ge=60,le=43200);enabled:bool=True
@app.post('/api/schedules')
def add_schedule(x:ScheduleIn,authorization:str|None=Header(None),db:Session=Depends(get_db)):
 u=auth(authorization,db);t=db.get(Target,x.target_id);sc=db.get(Scope,x.scope_id)
 if not t or not sc or not sc.authorization_confirmed or sc.target_id!=t.id:raise HTTPException(400,'Invalid target/scope')
 sch=Schedule(target_id=t.id,scope_id=sc.id,frequency_minutes=x.frequency_minutes,enabled=x.enabled,next_run=__import__('datetime').datetime.utcnow()+__import__('datetime').timedelta(minutes=x.frequency_minutes));db.add(sch);db.add(AuditLog(username=u.username,action='create_schedule',details=f'schedule={sch.id}'));db.commit();db.refresh(sch);return {'id':sch.id}
@app.post('/api/schedules/{sid}/toggle')
def toggle_schedule(sid:int,authorization:str|None=Header(None),db:Session=Depends(get_db)):
 auth(authorization,db);sch=db.get(Schedule,sid)
 if not sch:raise HTTPException(404,'Not found')
 sch.enabled=not sch.enabled;db.commit();return {'enabled':sch.enabled}
@app.get('/api/data/{kind}')
def data(kind:str,authorization:str|None=Header(None),db:Session=Depends(get_db)):
 auth(authorization,db)
 allowed={
  'targets':Target,'assets':Asset,'dns':DNSRecord,'services':HTTPService,'technologies':Technology,'urls':URL,'endpoints':Endpoint,'findings':Finding,'logs':Log,'tool-runs':ToolRun,'reports':Report,'audit':AuditLog}
 cls=allowed.get(kind)
 if not cls: raise HTTPException(404,'Unknown resource')
 rows=db.execute(select(cls).order_by(cls.id.desc()).limit(500)).scalars()
 return [{k:v for k,v in x.__dict__.items() if k!='_sa_instance_state'} for x in rows]

class VerifyCheckIn(BaseModel):
    url: str
    title: str = ''
    finding_type: str = ''

@app.post('/api/verify/finding/{fid}')
def verify_single_finding(fid: int, authorization: str | None = Header(None), db: Session = Depends(get_db)):
    import time
    u = auth(authorization, db)
    f = db.get(Finding, fid)
    if not f:
        raise HTTPException(404, 'Finding not found')
    from .verifier import verify_finding_deterministically
    res = verify_finding_deterministically(f.title, f.url, evidence=f.evidence)
    f.verification = res['status']
    f.confidence = f"{res['confidence']}% DETERMINISTIC"
    f.evidence = (f.evidence or '') + f"\n\n[VERIFICATION AUDIT {time.strftime('%Y-%m-%d %H:%M:%S')}]:\nStatus: {res['status']}\nReason: {res['reason']}\nTechnical Proof: {res['technical_proof']}"
    db.add(AuditLog(username=u.username, action='verify_finding', details=f"finding_id={fid} status={res['status']} url={f.url}"))
    db.commit()
    db.refresh(f)
    return {
        'id': f.id,
        'title': f.title,
        'url': f.url,
        'status': res['status'],
        'confidence': res['confidence'],
        'reason': res['reason'],
        'technical_proof': res['technical_proof'],
        'diff_details': res['diff_details']
    }

@app.post('/api/verify/check')
def verify_arbitrary_check(x: VerifyCheckIn, authorization: str | None = Header(None), db: Session = Depends(get_db)):
    auth(authorization, db)
    from .verifier import verify_finding_deterministically
    return verify_finding_deterministically(x.title, x.url, finding_type=x.finding_type)

@app.post('/api/verify/batch')
def verify_batch_findings(authorization: str | None = Header(None), db: Session = Depends(get_db)):
    u = auth(authorization, db)
    from .verifier import verify_finding_deterministically
    findings = db.execute(select(Finding).where(Finding.verification == 'UNVERIFIED').limit(100)).scalars().all()
    confirmed = 0
    false_positives = 0
    results = []
    for f in findings:
        res = verify_finding_deterministically(f.title, f.url, evidence=f.evidence)
        f.verification = res['status']
        f.confidence = f"{res['confidence']}% DETERMINISTIC"
        f.evidence = (f.evidence or '') + f"\n\n[VERIFICATION AUDIT]: {res['status']} - {res['reason']}"
        if res['status'] == 'CONFIRMED':
            confirmed += 1
        else:
            false_positives += 1
        results.append({'id': f.id, 'title': f.title, 'status': res['status'], 'reason': res['reason']})
    db.add(AuditLog(username=u.username, action='batch_verify', details=f"total={len(findings)} confirmed={confirmed} false_positives={false_positives}"))
    db.commit()
    return {
        'total_processed': len(findings),
        'confirmed': confirmed,
        'false_positives': false_positives,
        'results': results
    }

@app.get('/api/reports/{sid}/{fmt}')
def report(sid:int,fmt:str,authorization:str|None=Header(None),db:Session=Depends(get_db)):
 auth(authorization,db)
 fmt = fmt.lower()
 r=db.execute(select(Report).where(Report.scan_id==sid,Report.fmt==fmt)).scalars().first()
 p = Path(r.path) if r else None
 if not p or not p.exists():
  s = db.get(Scan, sid)
  if not s: raise HTTPException(404, 'Scan not found')
  target_root = s.target.root if (getattr(s, 'target', None) and s.target) else 'target.local'
  from .reporting import data as r_data, write_json, write_html, write_csv, write_text, write_pdf
  rows = lambda cls: [x.__dict__ for x in db.execute(select(cls).where(cls.scan_id==sid)).scalars()]
  d = r_data(
   {'id':sid,'profile':s.profile,'status':s.status,'started_at':s.started_at,'finished_at':s.finished_at},
   target_root,
   rows(Asset), rows(HTTPService), rows(Technology), rows(URL), rows(Endpoint), rows(Finding), rows(Log), rows(ToolRun)
  )
  fn_map = {'pdf': write_pdf, 'txt': write_text, 'html': write_html, 'json': write_json, 'csv': write_csv}
  fn = fn_map.get(fmt)
  if not fn: raise HTTPException(400, f'Unsupported format: {fmt}')
  p = fn(d, sid)
  if not r:
   db.add(Report(scan_id=sid, fmt=fmt, path=str(p)))
   db.commit()

 media_types = {
  'json': 'application/json',
  'html': 'text/html; charset=utf-8',
  'csv': 'text/csv; charset=utf-8',
  'txt': 'text/plain; charset=utf-8',
  'pdf': 'application/pdf'
 }
 return Response(p.read_bytes(), media_type=media_types.get(fmt, 'application/octet-stream'), headers={'Content-Disposition': f'attachment; filename="{p.name}"'})

@app.post('/api/reports/{sid}/generate')
def generate_report(sid:int, authorization:str|None=Header(None), db:Session=Depends(get_db)):
 auth(authorization, db)
 s = db.get(Scan, sid)
 if not s: raise HTTPException(404, 'Scan not found')
 target_root = s.target.root if (getattr(s, 'target', None) and s.target) else 'target.local'
 from .reporting import data as r_data, write_json, write_html, write_csv, write_text, write_pdf
 rows = lambda cls: [x.__dict__ for x in db.execute(select(cls).where(cls.scan_id==sid)).scalars()]
 d = r_data(
  {'id':sid,'profile':s.profile,'status':s.status,'started_at':s.started_at,'finished_at':s.finished_at},
  target_root,
  rows(Asset), rows(HTTPService), rows(Technology), rows(URL), rows(Endpoint), rows(Finding), rows(Log), rows(ToolRun)
 )
 generated = []
 for fmt, fn in [('pdf', write_pdf), ('txt', write_text), ('html', write_html), ('json', write_json), ('csv', write_csv)]:
  try:
   p = fn(d, sid)
   r = db.execute(select(Report).where(Report.scan_id==sid, Report.fmt==fmt)).scalars().first()
   if not r:
    db.add(Report(scan_id=sid, fmt=fmt, path=str(p)))
   else:
    r.path = str(p)
   generated.append(fmt)
  except Exception: pass
 db.commit()
 return {'status': 'ok', 'formats': generated}

@app.post('/api/data/purge')
def purge_all(authorization:str|None=Header(None), db:Session=Depends(get_db)):
 u = auth(authorization, db)
 from sqlalchemy import delete
 from .config import settings
 rep_dir = Path(settings.report_dir)
 if rep_dir.exists():
  for f in rep_dir.glob('basha-*'):
   try: f.unlink()
   except Exception: pass
 for model in [Report, Evidence, Finding, ToolRun, Log, Endpoint, URL, Technology, HTTPService, DNSRecord, Asset, Scan]:
  try: db.execute(delete(model))
  except Exception: pass
 db.add(AuditLog(username=u.username, action='purge_all_data', details='Purged all scans, findings, reports, and logs'))
 db.commit()
 return {'status': 'ok', 'message': 'تم حذف وتصفير كافة السجلات والتقارير بنجاح'}

@app.delete('/api/scans/{sid}')
def delete_scan(sid:int, authorization:str|None=Header(None), db:Session=Depends(get_db)):
 u = auth(authorization, db)
 s = db.get(Scan, sid)
 if not s: raise HTTPException(404, 'Scan not found')
 from sqlalchemy import delete
 from .config import settings
 rep_dir = Path(settings.report_dir)
 if rep_dir.exists():
  for f in rep_dir.glob(f'basha-{sid}.*'):
   try: f.unlink()
   except Exception: pass
 for model in [Report, Finding, ToolRun, Log, Endpoint, URL, Technology, HTTPService, DNSRecord, Asset]:
  try: db.execute(delete(model).where(model.scan_id == sid))
  except Exception: pass
 db.delete(s)
 db.add(AuditLog(username=u.username, action='delete_scan', details=f'Deleted scan #{sid}'))
 db.commit()
 return {'status': 'ok', 'message': f'Scan #{sid} deleted successfully'}
@app.websocket('/ws/scans/{sid}')
async def ws(websocket:WebSocket,sid:int):
 await websocket.accept()
 try:
  import asyncio
  while True:
   db=SessionLocal();s=db.get(Scan,sid);logs=db.execute(select(Log).where(Log.scan_id==sid).order_by(Log.id.desc()).limit(100)).scalars().all();payload={'status':s.status if s else 'UNKNOWN','progress':s.progress if s else 0,'stage':s.current_stage if s else '','tool':s.current_tool if s else '','logs':[{'level':x.level,'message':x.message} for x in reversed(logs)]};db.close();await websocket.send_json(payload)
   if not s or s.status in {'COMPLETED','FAILED','CANCELLED'}:break
   await asyncio.sleep(2)
 except WebSocketDisconnect:pass
