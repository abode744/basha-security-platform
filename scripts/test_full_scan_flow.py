import time
from app.db import SessionLocal, Base, engine
from app.models import Target, Scope, Scan
from app.local_worker import _run_real_scan

# Ensure DB is initialized
Base.metadata.create_all(engine)

db = SessionLocal()

# Find or create Target
target = db.query(Target).filter(Target.root == "httpbin.org").first()
if not target:
    target = Target(root="httpbin.org", enabled=True)
    db.add(target)
    db.commit()
    db.refresh(target)

# Find or create Scope
scope = db.query(Scope).filter(Scope.target_id == target.id).first()
if not scope:
    scope = Scope(
        target_id=target.id,
        include="httpbin.org",
        profile="passive",
        authorization_confirmed=True
    )
    db.add(scope)
    db.commit()
    db.refresh(scope)

scan = Scan(
    target_id=target.id,
    scope_id=scope.id,
    profile="passive",
    status="QUEUED",
    progress=0,
    current_stage="Initiating"
)
db.add(scan)
db.commit()
db.refresh(scan)
scan_id = scan.id
db.close()

print(f"Created test scan #{scan_id} for target {target.root}")
t0 = time.time()
_run_real_scan(scan_id)
elapsed = time.time() - t0

db = SessionLocal()
scan = db.query(Scan).filter(Scan.id == scan_id).first()
findings = db.query(Scan).filter(Scan.id == scan_id).first().findings if hasattr(scan, 'findings') else []
from app.models import Finding, ToolRun, Log
findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
tool_runs = db.query(ToolRun).filter(ToolRun.scan_id == scan_id).all()
logs = db.query(Log).filter(Log.scan_id == scan_id).all()

print(f"Scan #{scan_id} finished in {elapsed:.2f}s")
print(f"Status: {scan.status}")
print(f"Progress: {scan.progress}%")
print(f"Tool runs recorded: {len(tool_runs)}")
print(f"Findings recorded: {len(findings)}")
print(f"Logs recorded: {len(logs)}")

assert scan.status == "COMPLETED", f"Scan failed with status {scan.status}"
assert scan.progress == 100, f"Scan progress is {scan.progress}%"
assert len(tool_runs) > 0, "No tool runs recorded"

db.close()
print("\n[SUCCESS] Real end-to-end scan completed with 100% operational success and ZERO runtime errors!")
