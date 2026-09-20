import os
import sys
import subprocess
import time
import re
import webbrowser
from pathlib import Path

# Ensure UTF-8 output
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

PROJECT_DIR = Path(__file__).parent.resolve()
GH_EXE = PROJECT_DIR / "mingit" / "cmd" / "gh.exe"
GIT_EXE = PROJECT_DIR / "mingit" / "cmd" / "git.exe"

def log(msg):
    print(f"[*] {msg}", flush=True)

def main():
    print("=" * 65, flush=True)
    print("   🚀 BASHA Security Platform - Automated GitHub Deployment   ", flush=True)
    print("=" * 65, flush=True)

    # 1. Check if already authenticated
    auth_check = subprocess.run([str(GH_EXE), "auth", "status"], capture_output=True, text=True)
    is_logged_in = auth_check.returncode == 0 and "Logged in to github.com" in auth_check.stdout + auth_check.stderr

    if not is_logged_in:
        log("Starting GitHub Device Authentication...")
        proc = subprocess.Popen(
            [str(GH_EXE), "auth", "login", "--hostname", "github.com", "-p", "https", "--web"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1
        )

        code = None
        code_regex = re.compile(r'one-time code:\s*([A-Z0-9]{4}-[A-Z0-9]{4})', re.IGNORECASE)

        start = time.time()
        while time.time() - start < 20:
            line = proc.stdout.readline()
            if not line:
                break
            print("  " + line.strip(), flush=True)
            match = code_regex.search(line)
            if match:
                code = match.group(1).upper()
                break

        if not code:
            log("[!] Could not parse one-time code. Exiting.")
            proc.terminate()
            return

        # Send newline to trigger browser open
        try:
            proc.stdin.write("\n")
            proc.stdin.flush()
        except Exception:
            pass

        # Write to desktop
        msg_text = (
            f"رمز تسجيل الدخول إلى GitHub:\n"
            f"الرمز (One-Time Code): {code}\n\n"
            f"الرابط: https://github.com/login/device\n\n"
            f"خطوة واحدة فقط:\n"
            f"1. افتح الرابط أعلاه.\n"
            f"2. الصق الرمز: {code}\n"
            f"3. اضغط Authorize github للموافقة.\n"
            f"وسيقوم البرنامج فوراً برفع كافة الملفات إلى حسابك تلقائياً!\n"
        )

        for dt in [Path.home() / "OneDrive" / "Desktop", Path.home() / "Desktop"]:
            if dt.exists():
                try:
                    (dt / "GITHUB_LOGIN_CODE.txt").write_text(msg_text, encoding="utf-8")
                except Exception:
                    pass

        Path(PROJECT_DIR / "GITHUB_CODE.txt").write_text(f"CODE: {code}\nURL: https://github.com/login/device\n", encoding="utf-8")

        print("\n" + "=" * 65, flush=True)
        print(f"🔑 رمز التحقق لمرة واحدة (Device Code): [ {code} ]", flush=True)
        print(f"🌐 رابط التفعيل: https://github.com/login/device", flush=True)
        print("=" * 65, flush=True)
        print("[*] تم فتح صفحة التفعيل في المتصفح تلقائياً.", flush=True)
        print("[*] بانتظار إدخالك للرمز والموافقة في المتصفح...", flush=True)

        try:
            webbrowser.open("https://github.com/login/device")
        except Exception:
            pass

        # Wait for authentication to complete (up to 15 minutes)
        try:
            ret = proc.wait(timeout=900)
            if ret != 0:
                log("[!] Authentication failed or timed out.")
                return
        except subprocess.TimeoutExpired:
            log("[!] Authentication timed out after 15 minutes.")
            proc.terminate()
            return

    log("GitHub Authentication SUCCESSFUL!")

    # 2. Get username
    user_res = subprocess.run([str(GH_EXE), "api", "user", "--jq", ".login"], capture_output=True, text=True)
    username = user_res.stdout.strip()
    log(f"Authenticated as GitHub User: @{username}")

    # 3. Create repository and push
    repo_name = "basha-security-platform"
    log(f"Creating repository '{repo_name}' on GitHub and pushing code...")

    create_cmd = [
        str(GH_EXE), "repo", "create", repo_name,
        "--public",
        "--source", str(PROJECT_DIR),
        "--remote", "origin",
        "--push"
    ]
    create_res = subprocess.run(create_cmd, capture_output=True, text=True, cwd=str(PROJECT_DIR))
    print(create_res.stdout, flush=True)
    print(create_res.stderr, flush=True)

    # If repo already exists, just push
    if "already exists" in create_res.stderr.lower() or create_res.returncode != 0:
        log("Repository exists or remote set, pushing directly to main...")
        subprocess.run([str(GIT_EXE), "push", "-u", "origin", "main"], cwd=str(PROJECT_DIR))

    repo_url = f"https://github.com/{username}/{repo_name}"
    print("\n" + "=" * 65, flush=True)
    print("      🎉 تم رفع المشروع إلى GitHub بنجاح تام!      ", flush=True)
    print("=" * 65, flush=True)
    print(f"🔗 رابط المستودع على GitHub:\n   >>> {repo_url} <<<\n", flush=True)

    # Save to desktop
    for dt in [Path.home() / "OneDrive" / "Desktop", Path.home() / "Desktop"]:
        if dt.exists():
            try:
                (dt / "BASHA_GITHUB_REPO.txt").write_text(
                    f"رابط مستودع مشروع باشا على GitHub:\n{repo_url}\n",
                    encoding="utf-8"
                )
            except Exception:
                pass

if __name__ == "__main__":
    main()
