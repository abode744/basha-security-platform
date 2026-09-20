import os
import sys
import webbrowser
from pathlib import Path

# Ensure UTF-8 console output
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

PROJECT_DIR = Path(__file__).parent.resolve()

def main():
    print("=" * 65)
    print("   🤗 BASHA Security Platform - Deploy to Hugging Face Spaces   ")
    print("=" * 65)

    try:
        from huggingface_hub import HfApi, login
    except ImportError:
        print("[*] Installing huggingface_hub...")
        import subprocess
        subprocess.run([sys.executable, "-m", "pip", "install", "huggingface_hub"], check=True)
        from huggingface_hub import HfApi, login

    # Check for token in args, env, or prompt
    token = os.getenv("HF_TOKEN")
    if len(sys.argv) > 1 and sys.argv[1].startswith("hf_"):
        token = sys.argv[1].strip()

    if not token:
        token_file = Path.home() / ".cache" / "huggingface" / "token"
        if token_file.exists():
            token = token_file.read_text().strip()

    if not token:
        print("\n[*] للحصول على التوكن المجاني (بدون بطاقة بنكية):")
        print("    1. افتح الرابط: https://huggingface.co/settings/tokens")
        print("    2. اضغط 'Create new token' -> اختر نوع 'Write' -> اضغط 'Create'")
        print("    3. انسخ التوكن (يبدأ بـ hf_...)\n")
        try:
            webbrowser.open("https://huggingface.co/settings/tokens")
        except Exception:
            pass

        token = input("الصق توكن Hugging Face هنا (hf_...): ").strip()

    if not token:
        print("[!] لم يتم إدخال التوكن. تم الإلغاء.")
        return

    print("\n[*] جاري التحقق من التوكن والاتصال بـ Hugging Face...")
    try:
        api = HfApi(token=token)
        user_info = api.whoami()
        username = user_info["name"]
        print(f"[+] تم تسجيل الدخول بنجاح بحساب: @{username}")
    except Exception as e:
        print(f"[!] فشل التحقق من التوكن: {e}")
        return

    space_name = "basha-security-platform"
    repo_id = f"{username}/{space_name}"

    print(f"[*] جاري إنشاء مساحة العمل (Space) السحابية: {repo_id} ...")
    try:
        api.create_repo(
            repo_id=repo_id,
            repo_type="space",
            space_sdk="docker",
            exist_ok=True,
            private=False
        )
        print("[+] تم إنشاء / تجهيز الـ Space السحابي بنجاح!")
    except Exception as e:
        print(f"[*] ملاحظة أثناء إنشاء Space: {e}")

    print("[*] جاري رفع كافة ملفات المشروع إلى Hugging Face (بناء الحاوية السحابية)...")
    ignore_list = [
        "cloudflared.exe",
        "*.db",
        "*.sqlite3",
        "basha_local.db",
        "mingit/*",
        "mingit/**",
        ".git/*",
        ".git/**",
        "__pycache__/*",
        "__pycache__/**",
        ".pytest_cache/*",
        "PUBLIC_URL.txt",
        "GITHUB_CODE.txt",
        "reports/*.pdf",
        "reports/*.txt",
        "reports/*.html",
        "reports/*.csv",
        "reports/*.json"
    ]

    try:
        api.upload_folder(
            folder_path=str(PROJECT_DIR),
            repo_id=repo_id,
            repo_type="space",
            ignore_patterns=ignore_list,
            commit_message="Deploy BASHA Security Platform v1.0 with 20 tools"
        )
        print("\n" + "=" * 65)
        print("      🎉 تم رفع ونشر منصة باشا على Hugging Face Spaces بنجاح!   ")
        print("=" * 65)

        space_web_url = f"https://huggingface.co/spaces/{repo_id}"
        direct_app_url = f"https://{username.lower().replace('_', '-')}-{space_name.lower().replace('_', '-')}.hf.space"

        print(f"\n🌐 رابط إدارة المساحة (Space Dashboard):")
        print(f"   >>> {space_web_url} <<<\n")
        print(f"🚀 الرابط المباشر للتطبيق (Direct Web App URL):")
        print(f"   >>> {direct_app_url} <<<\n")
        print("🔐 بيانات تسجيل الدخول الافتراضية:")
        print("   اسم المستخدم: abod")
        print("   كلمة المرور : 2024")
        print("=" * 65)
        print("[*] جاري الآن بناء حاوية Docker على خوادم Hugging Face.")
        print("[*] سيصبح الموقع متاحاً وتعمل حاويته خلال دقيقة أو دقيقتين تلقائياً.")

        # Save to desktop
        msg = (
            f"رابط منصة باشا على Hugging Face Spaces (مجاني 24/7):\n"
            f"رابط لوحة التحكم: {space_web_url}\n"
            f"رابط الموقع المباشر: {direct_app_url}\n\n"
            f"اسم المستخدم: abod\n"
            f"كلمة المرور: 2024\n"
        )
        for dt in [Path.home() / "OneDrive" / "Desktop", Path.home() / "Desktop"]:
            if dt.exists():
                try:
                    (dt / "HUGGINGFACE_DEPLOY_LINK.txt").write_text(msg, encoding="utf-8")
                except Exception:
                    pass

        try:
            webbrowser.open(space_web_url)
        except Exception:
            pass

    except Exception as e:
        print(f"[!] حدث خطأ أثناء رفع الملفات: {e}")

if __name__ == "__main__":
    main()
