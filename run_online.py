"""
BASHA Online Auto-Launcher via Cloudflare Global Edge
المشغل السحابي التلقائي لمنصة باشا - يولد رابط إنترنت عام مشفر وفوري
"""

import os
import sys
import subprocess
import threading
import time
import re
import socket
from pathlib import Path
import webbrowser

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

def free_port(port):
    try:
        cmd = f"netstat -aon | findstr :{port} | findstr LISTENING"
        output = subprocess.check_output(cmd, shell=True).decode()
        for line in output.splitlines():
            parts = line.strip().split()
            if len(parts) >= 5:
                pid = parts[-1]
                if pid.isdigit() and int(pid) != os.getpid():
                    print(f"[*] Port {port} is occupied by PID {pid}. Freeing...")
                    subprocess.call(f"taskkill /F /PID {pid}", shell=True)
                    time.sleep(1)
    except Exception:
        pass

def start_server():
    free_port(8080)
    # Enforce SQLite
    os.environ["DATABASE_URL"] = "sqlite:///./basha_local.db"
    os.environ["BASHA_ADMIN_USER"] = "abod"
    os.environ["BASHA_ADMIN_PASSWORD"] = "2024"

    from app.db import Base, engine, SessionLocal
    from app.models import User
    from app.security import hash_password
    Base.metadata.create_all(engine)
    db = SessionLocal()
    u = db.query(User).filter_by(username="abod").first()
    if not u:
        db.add(User(username="abod", password_hash=hash_password("2024"), role="admin"))
        db.commit()
    db.close()

    import uvicorn
    from app.main import app
    uvicorn.run(app, host="127.0.0.1", port=8080, log_level="warning")

def main():
    print("=" * 65)
    print("      [+] BASHA Security Platform - Launching Online Global URL   ")
    print("=" * 65)
    print("[*] Starting backend API on http://127.0.0.1:8080 ...")

    # Start Uvicorn in background thread
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()

    # Wait for local port 8080 to be active
    time.sleep(2)

    # Locate cloudflared.exe
    cf_path = Path(__file__).parent / "cloudflared.exe"
    if not cf_path.exists():
        print("[*] Downloading cloudflared.exe from official Cloudflare repository...")
        import urllib.request
        url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"
        urllib.request.urlretrieve(url, str(cf_path))

    print("[*] Establishing secure Cloudflare Tunnel to the internet...")
    cf_proc = subprocess.Popen(
        [str(cf_path), "tunnel", "--url", "http://127.0.0.1:8080"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1
    )

    public_url = None
    url_regex = re.compile(r'https://[a-zA-Z0-9-]+\.trycloudflare\.com')

    # Read output to extract public URL
    start_time = time.time()
    while time.time() - start_time < 35:
        line = cf_proc.stdout.readline()
        if not line:
            break
        match = url_regex.search(line)
        if match:
            public_url = match.group(0)
            break

    if public_url:
        print("\n" + "=" * 65)
        print("          [+] تم تشغيل ورفع الموقع على الانترنت بنجاح!           ")
        print("=" * 65)
        print(f"\n[+] الرابط العام المباشر (يمكن فتحه من اي جهاز في العالم):")
        print(f"   >>> {public_url} <<<\n")
        print("[+] بيانات تسجيل الدخول:")
        print("   اسم المستخدم : abod")
        print("   كلمة المرور  : 2024")
        print("=" * 65)
        print("[*] ملاحظة: الرابط يعمل الآن ومفتوح عبر الإنترنت.")
        print("[*] لإيقاف الموقع: اضغط Ctrl + C في هذه النافذة.\n")

        # Save to file
        Path("PUBLIC_URL.txt").write_text(f"URL: {public_url}\nUser: abod\nPass: 2024\n", encoding="utf-8")
        for dt in [Path.home() / "OneDrive" / "Desktop", Path.home() / "Desktop"]:
            if dt.exists():
                try:
                    (dt / "BASHA_ONLINE_LINK.txt").write_text(
                        f"رابط منصة باشا على الإنترنت:\n{public_url}\n\nاسم المستخدم: abod\nكلمة المرور: 2024\n",
                        encoding="utf-8"
                    )
                except Exception:
                    pass

        try:
            webbrowser.open(public_url)
        except Exception:
            pass

        # Keep running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Shutting down online tunnel...")
            cf_proc.terminate()
    else:
        print("[!] Could not retrieve public URL. Check internet connection.")

if __name__ == "__main__":
    main()
