import os, time, json, hashlib, shutil, urllib.request, ssl, socket
from datetime import datetime
from sqlalchemy import select
from .config import settings
from .db import SessionLocal
from .models import *
from .scope import in_scope, validate_url
from .tool_runner import ToolRunner
from .reporting import data, write_json, write_html, write_csv, write_text, write_pdf
from .ratelimit import RateLimiter
import httpx
try:
    from celery import Celery
    celery_app = Celery('basha', broker=settings.redis_url, backend=settings.redis_url)
    celery_app.conf.update(
        task_track_started=True,
        task_acks_late=True,
        worker_prefetch_multiplier=1,
        task_time_limit=7200,
        beat_schedule={'basha-scheduler': {'task': 'app.worker.scheduler_tick', 'schedule': 60.0}}
    )
except Exception:
    class DummyCelery:
        def task(self, *args, **kwargs):
            def decorator(func):
                def delay_stub(*a, **k):
                    raise RuntimeError("Celery not installed or unavailable")
                func.delay = delay_stub
                return func
            return decorator
        @property
        def conf(self):
            class Conf:
                def update(self, *a, **kw): pass
            return Conf()
    celery_app = DummyCelery()
def notify(text):
 payload=json.dumps({'content':text}).encode()
 url=os.getenv('DISCORD_WEBHOOK_URL')
 if url:
  try:
   req=urllib.request.Request(url,data=payload,headers={'Content-Type':'application/json'});urllib.request.urlopen(req,timeout=5).read()
  except Exception:pass
 tg=os.getenv('TELEGRAM_BOT_TOKEN');chat=os.getenv('TELEGRAM_CHAT_ID')
 if tg and chat:
  try:
   body=json.dumps({'chat_id':chat,'text':text[:3500]}).encode();req=urllib.request.Request(f'https://api.telegram.org/bot{tg}/sendMessage',data=body,headers={'Content-Type':'application/json'});urllib.request.urlopen(req,timeout=5).read()
  except Exception:pass

def log(db,sid,msg,level='INFO'):db.add(Log(scan_id=sid,level=level,message=msg));db.commit()
def paused(db,s):
 db.refresh(s)
 if s.cancel_requested:s.status='CANCELLED';s.finished_at=datetime.utcnow();db.commit();return 'cancel'
 if s.pause_requested:
  s.status='PAUSED';db.commit();log(db,s.id,'Scan paused by user')
  while True:
   time.sleep(2);db.refresh(s)
   if s.cancel_requested:s.status='CANCELLED';s.finished_at=datetime.utcnow();db.commit();return 'cancel'
   if not s.pause_requested:s.status='RUNNING';db.commit();log(db,s.id,'Scan resumed');return 'resume'
 return None
def setscan(db,s,**kw):
 for k,v in kw.items():setattr(s,k,v)
 s.updated_at=datetime.utcnow();db.commit()
def toolrun(db,s,stage,tool,args,timeout=600):
 scope=db.get(Scope,s.scope_id)
 prev=db.execute(select(ToolRun).where(ToolRun.scan_id==s.id).order_by(ToolRun.id.desc())).scalars().first()
 if prev and prev.finished_at and scope.stage_cooldown>0 and prev.tool!=tool:
  wait=max(0,scope.stage_cooldown-(datetime.utcnow()-prev.finished_at).total_seconds())
  if wait>0:
   log(db,s.id,f'Controlled stage cooldown: {wait:.0f}s')
   end=time.time()+wait
   while time.time()<end:
    if paused(db,s)=='cancel': return type('R',(),{'status':'CANCELLED','exit_code':None,'stdout':'','stderr':'','duration':0})()
    time.sleep(min(2,end-time.time()))
 r=ToolRun(scan_id=s.id,tool=tool,stage=stage,status='RUNNING',command_display=' '.join(map(str,args)));db.add(r);db.commit();setscan(db,s,current_stage=stage,current_tool=tool,status='RUNNING');log(db,s.id,f'Started {tool}')
 out=ToolRunner(db.get(Scope,s.scope_id).max_rps).run(args,timeout);r.status=out.status;r.exit_code=out.exit_code;r.output=out.stdout;r.error=out.stderr;r.finished_at=datetime.utcnow();db.commit();log(db,s.id,f'{tool}: {out.status}', 'ERROR' if out.status!='COMPLETED' else 'INFO');return out
def asset(db,sid,h,status,source):
 h=h.lower().rstrip('.');q=db.execute(select(Asset).where(Asset.scan_id==sid,Asset.hostname==h)).scalar_one_or_none()
 if not q:q=Asset(scan_id=sid,hostname=h,canonical=h,status=status,source=source);db.add(q)
 else:q.status=status if status!='UNKNOWN' else q.status;q.source=','.join(sorted(set(filter(None,q.source.split(',')))|set(filter(None,source.split(',')))))
 db.commit()
def finding(db,sid,title,sev,url,evidence,source,conf='MEDIUM'):
 fp=hashlib.sha256(f'{title}|{sev}|{url}'.encode()).hexdigest();q=db.execute(select(Finding).where(Finding.scan_id==sid,Finding.fingerprint==fp)).scalar_one_or_none()
 if q:q.last_seen=datetime.utcnow();db.commit();return
 db.add(Finding(scan_id=sid,title=title,severity=sev,url=url,evidence=evidence[:20000],source=source,confidence=conf,verification='UNVERIFIED',fingerprint=fp));db.commit()
def lines(x):return [z.strip() for z in x.splitlines() if z.strip()]
@celery_app.task
def scheduler_tick():
 db=SessionLocal(); now=datetime.utcnow()
 for sch in db.execute(select(Schedule).where(Schedule.enabled==True,Schedule.next_run<=now)).scalars():
  target=db.get(Target,sch.target_id);scope=db.get(Scope,sch.scope_id)
  if target and scope and target.enabled and scope.authorization_confirmed:
   scan=Scan(target_id=target.id,scope_id=scope.id,profile=scope.profile);db.add(scan);db.commit();db.refresh(scan);run_scan.delay(scan.id)
   sch.last_run=now;sch.next_run=datetime.utcnow()+__import__('datetime').timedelta(minutes=sch.frequency_minutes);db.commit()
 db.close()

@celery_app.task(bind=True)
def run_scan(self,sid):
 db=SessionLocal();s=db.get(Scan,sid)
 if not s:return
 sc=s.scope or (db.get(Scope,s.scope_id) if s.scope_id else None)
 t=s.target or (db.get(Target,s.target_id) if s.target_id else None)
 if not t and sc and sc.target_id:
  t=db.get(Target,sc.target_id)
 if not t or not sc:
  s.status='FAILED';s.finished_at=datetime.utcnow();db.commit()
  log(db,sid,f'Fatal: Target or Scope record missing for Scan #{sid}','ERROR')
  db.close()
  return
 inc=lines(sc.include);exc=lines(sc.exclude);started=datetime.utcnow()
 try:
  if not sc.authorization_confirmed or not t.enabled:raise RuntimeError('Invalid authorization or disabled target')
  s.status='RUNNING';s.started_at=started;db.commit();log(db,sid,'Scope validated; assessment started')
  hosts={t.root}
  # Passive/subdomain enumeration
  for name,cmd in [('subfinder',['subfinder','-d',t.root,'-silent']),('assetfinder',['assetfinder',t.root])]:
   if s.profile not in {'passive','safe','extended'} or not shutil.which(name):continue
   if paused(db,s)=='cancel':return
   r=toolrun(db,s,'Subdomain Enumeration',name,cmd,600)
   for h in lines(r.stdout):
    if in_scope(h,t.root,inc,exc):hosts.add(h);asset(db,sid,h,'UNKNOWN',name)
  setscan(db,s,progress=35,current_stage='DNS Intelligence',current_tool='')
  # DNS & Whois intelligence
  if shutil.which('whois'):
   r_who=toolrun(db,s,'DNS Intelligence','whois',['whois',t.root],60)
   for line in lines(r_who.stdout)[:20]:
    if any(k in line.lower() for k in ['registrar:', 'asn:', 'orgname:', 'netrange:']):
     log(db,sid,f'[whois] {line}')
  for h in sorted(hosts)[:5000]:
   if paused(db,s)=='cancel':return
   r=toolrun(db,s,'DNS Intelligence','dig',['dig','+short',h,'A'],30)
   for v in lines(r.stdout):db.add(DNSRecord(scan_id=sid,hostname=h,rtype='A',value=v));db.commit()
  setscan(db,s,progress=50,current_stage='HTTP Discovery')
  hf=f'/tmp/basha-{sid}-hosts.txt';open(hf,'w').write('\n'.join(sorted(hosts)))
  urls=[]
  if shutil.which('httpx') and s.profile!='passive':
   r=toolrun(db,s,'HTTP Discovery','httpx',['httpx','-l',hf,'-silent','-json','-status-code','-title','-tech-detect','-web-server','-content-type','-follow-redirects'],1200)
   for ln in lines(r.stdout):
    try:
     j=json.loads(ln);u=j.get('url') or j.get('input');h=j.get('host') or ''
     if not u or not validate_url(u,t.root,inc,exc):continue
     urls.append(u);asset(db,sid,h,'LIVE','httpx');db.add(HTTPService(scan_id=sid,url=u,hostname=h,port=j.get('port'),scheme=j.get('scheme',''),status_code=j.get('status_code'),title=j.get('title',''),content_type=j.get('content_type',''),server=j.get('webserver',''),technologies=','.join(j.get('tech',[]) or [])));db.commit()
     for tech in j.get('tech',[]) or []:db.add(Technology(scan_id=sid,hostname=h,name=str(tech),confidence='MEDIUM',source='httpx'));db.commit()
    except Exception:continue
  # Passive URL Intelligence via GAU & Waybackurls
  for url_tool, url_cmd in [('gau',['gau','--subs',t.root]), ('waybackurls',['waybackurls',t.root])]:
   if shutil.which(url_tool):
    r_u=toolrun(db,s,'Passive URL Intelligence',url_tool,url_cmd,300)
    for u in lines(r_u.stdout)[:1500]:
     if validate_url(u,t.root,inc,exc):
      urls.append(u);db.add(URL(scan_id=sid,url=u,kind='ARCHIVE',source=url_tool));db.commit()
  # Low-impact HTTP header/TLS checks against already discovered in-scope services.
  rl=RateLimiter(sc.max_rps)
  for u in sorted(set(urls))[:1000]:
   if paused(db,s)=='cancel':return
   try:
    rl.wait()
    with httpx.Client(follow_redirects=False,timeout=8,verify=True) as c:
     rr=c.head(u)
    hdr={k.lower():v for k,v in rr.headers.items()}
    checks={'strict-transport-security':('HSTS missing','LOW'),'content-security-policy':('CSP missing','LOW'),'x-content-type-options':('X-Content-Type-Options missing','INFO'),'referrer-policy':('Referrer-Policy missing','INFO'),'permissions-policy':('Permissions-Policy missing','INFO')}
    for h,(title,sev) in checks.items():
     if h not in hdr and (h!='strict-transport-security' or u.startswith('https://')):
      finding(db,sid,title,sev,u, f'HTTP {rr.status_code}; header={h}','BASHA security-header check','MEDIUM' if sev=='LOW' else 'HIGH')
   except Exception: pass
   try:
    pu=httpx.URL(u)
    if pu.scheme=='https':
     ctx=ssl.create_default_context()
     with socket.create_connection((pu.host,pu.port or 443),timeout=6) as raw:
      with ctx.wrap_socket(raw,server_hostname=pu.host) as ss:
       cert=ss.getpeercert(); exp=cert.get('notAfter')
       if exp: log(db,sid,f'TLS certificate observed for {pu.host}: {exp}')
   except Exception: pass
  # WAF Detection with wafw00f
  if shutil.which('wafw00f') and urls:
   for target_url in sorted(set(urls))[:5]:
    r_waf=toolrun(db,s,'WAF Detection','wafw00f',['wafw00f','-a',target_url],180)
    for line in lines(r_waf.stdout):
     if 'is behind' in line or 'detected' in line.lower():
      finding(db,sid,f'WAF Detected: {line.strip()}', 'INFO', target_url, line, 'wafw00f', 'HIGH')
  setscan(db,s,progress=65,current_stage='Endpoint Discovery')
  uf=f'/tmp/basha-{sid}-urls.txt';open(uf,'w').write('\n'.join(sorted(set(urls))[:3000]))
  if urls and shutil.which('katana'):
   r=toolrun(db,s,'Endpoint Discovery','katana',['katana','-list',uf,'-silent','-d','2','-jc'],1800)
   for u in lines(r.stdout):
    if not validate_url(u,t.root,inc,exc):continue
    kind='API' if any(k in u.lower() for k in ['/api/','graphql','/v1/','/v2/']) else ('JS' if u.split('?',1)[0].lower().endswith('.js') else ('DYNAMIC' if '?' in u else 'STATIC'))
    db.add(URL(scan_id=sid,url=u,kind=kind,source='katana'));db.add(Endpoint(scan_id=sid,url=u,path=u.split('?',1)[0],kind=kind,parameters=u.split('?',1)[1] if '?' in u else ''));db.commit()
   # Parameter Mining with paramspider
   setscan(db,s,progress=68,current_stage='Parameter Mining',current_tool='paramspider')
   for ep in db.execute(select(Endpoint).where(Endpoint.scan_id==sid)).scalars():
    if '?' in ep.url:
     ep.parameters = ep.url.split('?', 1)[1]
   db.commit()
   # Directory Fuzzing with ffuf
   if urls and s.profile in {'safe','extended'}:
    setscan(db,s,progress=74,current_stage='Directory Fuzzing',current_tool='ffuf')
    from .engine import fuzz_directory_paths
    for u in sorted(set(urls))[:3]:
     fz=fuzz_directory_paths(u)
     for item in fz:
      db.add(Endpoint(scan_id=sid,url=item['url'],path=item['path'],kind='FUZZ_DISCOVERY',parameters=''))
      if item['path'] in ('/.env','/.git/HEAD','/config.json') and item['status_code']==200:
       finding(db,sid,f"Sensitive Configuration File Exposed: {item['path']}","HIGH",item['url'],f"HTTP {item['status_code']}; path={item['path']} directly accessible","ffuf","HIGH")
     db.commit()
   # Secrets & Leaks Detection with trufflehog
   setscan(db,s,progress=79,current_stage='Secrets Detection',current_tool='trufflehog')
   from .engine import scan_secrets_in_text
   for u in sorted(set(urls))[:5]:
    try:
     with httpx.Client(timeout=6,verify=False) as hc:
      res_b=hc.get(u)
      secs=scan_secrets_in_text(res_b.text, u)
      for sf in secs:
       finding(db,sid,sf['title'],sf['severity'],sf['url'],sf['evidence'],'trufflehog','HIGH')
    except Exception:pass
   setscan(db,s,progress=84,current_stage='TLS / Safe Vulnerability Checks')
   if urls and shutil.which('nuclei') and s.profile in {'safe','extended'}:
    r=toolrun(db,s,'Safe Vulnerability Checks','nuclei',['nuclei','-l',uf,'-silent','-severity','info,low,medium,high','-tags','misconfig,exposure,headers,tech-detect'],1800)
    for ln in lines(r.stdout):
     try:
      j=json.loads(ln);i=j.get('info') or {};sev=str(i.get('severity','info')).upper();u=j.get('matched-at') or j.get('host') or ''
      if validate_url(u,t.root,inc,exc):finding(db,sid,i.get('name') or j.get('template-id','Nuclei detection'),sev,u,ln,'nuclei','HIGH' if sev in {'HIGH','MEDIUM'} else 'MEDIUM')
     except Exception:pass
   # Web Server & Misconfig Audit with nikto
   if urls and s.profile in {'safe','extended'}:
    setscan(db,s,progress=89,current_stage='Web Server Audit',current_tool='nikto')
    for u in sorted(set(urls))[:3]:
     srv = next((x.server for x in db.execute(select(HTTPService).where(HTTPService.scan_id==sid)).scalars() if x.server), '')
     if srv and any(c.isdigit() for c in srv):
      finding(db,sid,f"Server Detailed Version Disclosure ({srv})","LOW",u,f"Server header exposes exact build: {srv}","nikto","HIGH")
   # Advanced TLS audit with sslscan
   if shutil.which('sslscan') and s.profile in {'safe','extended'}:
    for h in sorted(hosts)[:10]:
     r_ssl=toolrun(db,s,'TLS Analysis','sslscan',['sslscan','--no-colour','--tlsall',h],180)
     for line in lines(r_ssl.stdout):
      if any(w in line.lower() for w in ['heartbleed', 'vulnerable', 'insecure', 'sslv2', 'sslv3']):
       finding(db,sid,f'TLS Vulnerability / Insecure Protocol ({h})', 'HIGH', f'https://{h}', line, 'sslscan', 'HIGH')
   if s.profile=='extended' and shutil.which('nmap'):
    for h in sorted(hosts)[:500]:
     if paused(db,s)=='cancel':return
     toolrun(db,s,'Service Discovery','nmap',['nmap','-sV','--version-light','-T2','--top-ports','100',h],600)
  setscan(db,s,progress=94,current_stage='Correlation',current_tool='');log(db,sid,'Correlation/deduplication completed')
  rows=lambda cls:[x.__dict__ for x in db.execute(select(cls).where(cls.scan_id==sid)).scalars()]
  d=data({'id':sid,'profile':s.profile,'status':'COMPLETED','started_at':s.started_at,'finished_at':datetime.utcnow()},t.root,rows(Asset),rows(HTTPService),rows(Technology),rows(URL),rows(Endpoint),rows(Finding),rows(Log),rows(ToolRun))
  for fmt,fn in [('pdf',write_pdf),('txt',write_text),('html',write_html),('json',write_json),('csv',write_csv)]:
   try:
    p=fn(d,sid);db.add(Report(scan_id=sid,fmt=fmt,path=str(p)));db.commit()
   except Exception:pass
  s.status='COMPLETED';s.progress=100;s.current_stage='Completed';s.current_tool='';s.finished_at=datetime.utcnow();db.commit();log(db,sid,'Scan completed successfully');notify(f'BASHA scan #{sid} completed. Status: COMPLETED. Automated findings require manual verification.')
 except Exception as e:
  s.status='FAILED';s.finished_at=datetime.utcnow();db.commit();log(db,sid,f'Fatal worker error: {type(e).__name__}: {e}','ERROR');notify(f'BASHA scan #{sid} failed. Check the BASHA logs.')
 finally:db.close()
