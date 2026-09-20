import os,subprocess,time
from dataclasses import dataclass
from .ratelimit import RateLimiter
SAFE_BINARIES={'subfinder','assetfinder','httpx','dnsx','katana','nuclei','nmap','dig','openssl'}
@dataclass
class ToolResult: status:str; exit_code:int|None; stdout:str; stderr:str; duration:float
class ToolRunner:
 def __init__(self,rps=1):self.rl=RateLimiter(rps)
 def run(self,args,timeout=300):
  if not args or os.path.basename(args[0]) not in SAFE_BINARIES:raise ValueError('Tool is not allowlisted')
  if any('\n' in str(a) or '\r' in str(a) for a in args):raise ValueError('Invalid command argument')
  self.rl.wait();st=time.monotonic()
  try:
   p=subprocess.run(args,capture_output=True,text=True,timeout=timeout,shell=False,cwd='/tmp')
   return ToolResult('COMPLETED' if p.returncode==0 else 'FAILED',p.returncode,p.stdout[-2000000:],p.stderr[-500000:],time.monotonic()-st)
  except subprocess.TimeoutExpired as e:return ToolResult('TIMEOUT',None,str(e.stdout or '')[-2000000:],str(e.stderr or '')[-500000:],time.monotonic()-st)
