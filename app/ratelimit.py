import time,threading
class RateLimiter:
 def __init__(self,rps=1):self.interval=1/max(float(rps),0.1);self.last=0;self.lock=threading.Lock()
 def wait(self):
  with self.lock:
   d=self.interval-(time.monotonic()-self.last)
   if d>0:time.sleep(d)
   self.last=time.monotonic()
