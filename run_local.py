import os
import sys
import subprocess
import webbrowser
import threading
import time
from datetime import datetime

# Automatic dependency checker & installer
def ensure_dependencies():
    packages = [
        ("fastapi", "fastapi"),
        ("uvicorn", "uvicorn[standard]"),
        ("sqlalchemy", "sqlalchemy"),
        ("bcrypt", "bcrypt"),
        ("jose", "python-jose"),
        ("httpx", "httpx"),
        ("pydantic_settings", "pydantic-settings"),
    ]
    for mod, pip_name in packages:
        try:
            __import__(mod)
        except ImportError:
            print(f"[*] Missing package '{mod}'. Installing {pip_name} automatically...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", pip_name])
            except Exception as e:
                print(f"[!] Failed to auto-install {pip_name}: {e}")

ensure_dependencies()

# Enforce local SQLite database for local standalone preview
os.environ["DATABASE_URL"] = "sqlite:///./basha_local.db"
os.environ["BASHA_SECRET_KEY"] = "b4eb051caf7549f0bb0261d23c901fe315f1007c260640488e5a7a9768bdc3e3"
os.environ["BASHA_ADMIN_USER"] = "abod"
os.environ["BASHA_ADMIN_PASSWORD"] = "2024"

from app.db import Base, engine, SessionLocal
from app.models import (
    User, Target, Scope, Scan, Asset, Finding, DNSRecord,
    HTTPService, Technology, Endpoint, Log, AuditLog, ToolRun
)
from app.security import hash_password

def seed_local_environment():
    Base.metadata.create_all(engine)
    db = SessionLocal()
    try:
        # 1. Admin user
        admin = db.query(User).filter_by(username="abod").first()
        if not admin:
            db.add(User(
                username="abod",
                password_hash=hash_password("2024"),
                role="admin"
            ))
            db.commit()
            print("[+] Initialized Admin Account: abod / 2024")

        # 2. Check if sample demo data is needed
        if db.query(Target).count() == 0:
            print("[*] Seeding realistic sample telemetry for local interactive preview...")
            t1 = Target(root="authorized-lab.internal", enabled=True)
            t2 = Target(root="secure-corp.net", enabled=True)
            db.add_all([t1, t2])
            db.commit()
            db.refresh(t1)
            db.refresh(t2)

            sc1 = Scope(
                target_id=t1.id,
                include="*.authorized-lab.internal",
                exclude="out-of-scope.authorized-lab.internal",
                excluded_paths="/logout, /delete",
                max_rps=1.0,
                stage_cooldown=60,
                profile="safe",
                authorization_confirmed=True
            )
            db.add(sc1)
            db.commit()
            db.refresh(sc1)

            # Completed Scan
            scan1 = Scan(
                target_id=t1.id,
                scope_id=sc1.id,
                profile="safe",
                status="COMPLETED",
                progress=100,
                current_stage="Completed",
                current_tool="reporter",
                started_at=datetime.utcnow(),
                finished_at=datetime.utcnow()
            )
            # In-progress Scan
            scan2 = Scan(
                target_id=t2.id,
                scope_id=sc1.id,
                profile="extended",
                status="RUNNING",
                progress=65,
                current_stage="HTTP & Service Discovery",
                current_tool="httpx",
                started_at=datetime.utcnow()
            )
            db.add_all([scan1, scan2])
            db.commit()
            db.refresh(scan1)
            db.refresh(scan2)

            # Assets
            assets = [
                Asset(scan_id=scan1.id, hostname="authorized-lab.internal", canonical="authorized-lab.internal", status="LIVE", source="subfinder", ips="10.0.1.15", ports="80, 443, 8080"),
                Asset(scan_id=scan1.id, hostname="api.authorized-lab.internal", canonical="api.authorized-lab.internal", status="LIVE", source="subfinder", ips="10.0.1.18", ports="443"),
                Asset(scan_id=scan1.id, hostname="vpn.authorized-lab.internal", canonical="vpn.authorized-lab.internal", status="LIVE", source="dnsx", ips="10.0.1.20", ports="443, 1194"),
                Asset(scan_id=scan1.id, hostname="dev.authorized-lab.internal", canonical="dev.authorized-lab.internal", status="LIVE", source="assetfinder", ips="10.0.1.25", ports="3000, 8080"),
            ]
            db.add_all(assets)

            # Findings
            findings = [
                Finding(
                    scan_id=scan1.id,
                    title="Exposed Git Configuration Repository (.git/config)",
                    severity="CRITICAL",
                    url="https://authorized-lab.internal/.git/config",
                    parameter="Path",
                    evidence="[core]\nrepositoryformatversion = 0\nfilemode = true\nbare = false\n[remote \"origin\"]\nurl = git@github.com:internal-lab/core-api.git",
                    source="nuclei",
                    confidence="HIGH",
                    verification="UNVERIFIED",
                    fingerprint="fp-git-exposed-lab"
                ),
                Finding(
                    scan_id=scan1.id,
                    title="Cross-Origin Resource Sharing (CORS) Wildcard Origin Misconfiguration",
                    severity="HIGH",
                    url="https://api.authorized-lab.internal/v1/auth",
                    parameter="Origin Header",
                    evidence="Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
                    source="nuclei",
                    confidence="HIGH",
                    verification="UNVERIFIED",
                    fingerprint="fp-cors-wildcard-lab"
                ),
                Finding(
                    scan_id=scan1.id,
                    title="Missing HTTP Strict-Transport-Security (HSTS) Header",
                    severity="MEDIUM",
                    url="https://authorized-lab.internal/",
                    parameter="HTTP Response Headers",
                    evidence="Strict-Transport-Security header was not detected in HTTP response.",
                    source="httpx",
                    confidence="HIGH",
                    verification="UNVERIFIED",
                    fingerprint="fp-hsts-missing-lab"
                ),
                Finding(
                    scan_id=scan1.id,
                    title="Server Version Banner Disclosure (nginx/1.24.0)",
                    severity="LOW",
                    url="https://authorized-lab.internal/",
                    parameter="Server",
                    evidence="Server: nginx/1.24.0 (Ubuntu)",
                    source="httpx",
                    confidence="HIGH",
                    verification="UNVERIFIED",
                    fingerprint="fp-nginx-banner-lab"
                ),
                Finding(
                    scan_id=scan1.id,
                    title="Cloudflare CDN Edge Protection Detected",
                    severity="INFO",
                    url="https://secure-corp.net/",
                    parameter="cf-ray",
                    evidence="cf-ray: 8df4091ab9102-DUB\nServer: cloudflare",
                    source="nuclei",
                    confidence="HIGH",
                    verification="UNVERIFIED",
                    fingerprint="fp-cloudflare-detected"
                )
            ]
            db.add_all(findings)

            # DNS Records
            dns_records = [
                DNSRecord(scan_id=scan1.id, hostname="authorized-lab.internal", rtype="A", value="10.0.1.15", source="dnsx"),
                DNSRecord(scan_id=scan1.id, hostname="authorized-lab.internal", rtype="MX", value="10 mail.authorized-lab.internal", source="dig"),
                DNSRecord(scan_id=scan1.id, hostname="authorized-lab.internal", rtype="TXT", value="v=spf1 include:_spf.authorized-lab.internal ~all", source="dig"),
                DNSRecord(scan_id=scan1.id, hostname="api.authorized-lab.internal", rtype="CNAME", value="gateway.authorized-lab.internal", source="dnsx")
            ]
            db.add_all(dns_records)

            # Endpoints
            endpoints = [
                Endpoint(scan_id=scan1.id, url="https://authorized-lab.internal/api/v1/health", path="/api/v1/health", kind="REST_API", parameters=""),
                Endpoint(scan_id=scan1.id, url="https://authorized-lab.internal/api/v1/auth/login", path="/api/v1/auth/login", kind="REST_API", parameters="username, password"),
                Endpoint(scan_id=scan1.id, url="https://authorized-lab.internal/swagger/v1/swagger.json", path="/swagger/v1/swagger.json", kind="API_SPEC", parameters=""),
                Endpoint(scan_id=scan1.id, url="https://dev.authorized-lab.internal/metrics", path="/metrics", kind="PROMETHEUS", parameters="")
            ]
            db.add_all(endpoints)

            # Technologies
            techs = [
                Technology(scan_id=scan1.id, hostname="authorized-lab.internal", name="Nginx", version="1.24.0", confidence="HIGH", source="httpx"),
                Technology(scan_id=scan1.id, hostname="authorized-lab.internal", name="FastAPI", version="0.115", confidence="HIGH", source="httpx"),
                Technology(scan_id=scan1.id, hostname="authorized-lab.internal", name="PostgreSQL", version="16", confidence="MEDIUM", source="nmap"),
                Technology(scan_id=scan1.id, hostname="dev.authorized-lab.internal", name="Node.js", version="20.11", confidence="HIGH", source="httpx")
            ]
            db.add_all(techs)

            # Logs
            logs = [
                Log(scan_id=scan1.id, level="INFO", message="[orchestrator] Initializing low-impact reconnaissance pipeline."),
                Log(scan_id=scan1.id, level="INFO", message="[subfinder] Enumerating subdomains via passive OSINT feeds."),
                Log(scan_id=scan1.id, level="INFO", message="[dnsx] Resolving DNS A, MX, CNAME records."),
                Log(scan_id=scan1.id, level="INFO", message="[httpx] Probing HTTP services, TLS certificates, and tech stacks."),
                Log(scan_id=scan1.id, level="WARN", message="[nuclei] Detected exposed Git repository configuration at /.git/config"),
                Log(scan_id=scan1.id, level="INFO", message="[reporter] Assessment pipeline finalized. Generating telemetry."),
            ]
            db.add_all(logs)

            # Audit Log
            db.add(AuditLog(username="admin", action="login", details="Initial session authenticated"))
            db.add(AuditLog(username="admin", action="create_scan", details="authorized-lab.internal scan=1"))

            db.commit()
            print("[+] Sample security reconnaissance data loaded successfully.")
    finally:
        db.close()

def free_port(port):
    try:
        output = subprocess.check_output("netstat -ano", shell=True).decode(errors="ignore")
        for line in output.strip().split("\n"):
            if f":{port}" in line and "LISTENING" in line:
                pid = line.strip().split()[-1]
                if pid != str(os.getpid()):
                    print(f"[*] Port {port} is occupied by previous process (PID {pid}). Freeing port...")
                    subprocess.call(f"taskkill /F /PID {pid}", shell=True)
                    time.sleep(1)
    except Exception:
        pass

def open_browser(port):
    time.sleep(1.5)
    print(f"\n[>>] Opening BASHA dashboard in your default browser: http://localhost:{port} ...\n")
    try:
        webbrowser.open(f"http://localhost:{port}")
    except Exception:
        pass

if __name__ == "__main__":
    print("=" * 60)
    print("       BASHA - Local Standalone Development Server        ")
    print("=" * 60)
    seed_local_environment()

    import socket
    import uvicorn
    from app.main import app

    free_port(8080)

    target_port = 8080
    for p in [8080, 8081, 8088, 8000]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("0.0.0.0", p))
                target_port = p
                break
        except OSError:
            continue

    print(f"[*] Starting Server on http://localhost:{target_port}")
    print("[*] Login Credentials -> Username: abod | Password: 2024")
    print("=" * 60)

    threading.Thread(target=open_browser, args=(target_port,), daemon=True).start()

    uvicorn.run(app, host="0.0.0.0", port=target_port, log_level="info")
