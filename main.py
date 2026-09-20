"""
BASHA Security Reconnaissance Platform - Entry Point
نقطة التشغيل الرئيسية لمنصة باشا (Replit & Cloud & Standalone)
"""

import os
import sys
import uvicorn
from app.db import Base, engine
from app import bootstrap

# Ensure database tables and default admin credentials exist
Base.metadata.create_all(engine)

def main():
    # Replit and cloud hosts assign the listening port via the PORT environment variable (default: 8080)
    port = int(os.environ.get("PORT", 8080))
    host = "0.0.0.0"

    print("=" * 60)
    print("   🚀 BASHA Security Platform - Running on Cloud / Replit   ")
    print("=" * 60)
    print(f"[*] Server Listening on : http://{host}:{port}")
    print("[*] Admin Username      : abod")
    print("[*] Admin Password      : 2024")
    print("=" * 60)

    uvicorn.run("app.main:app", host=host, port=port, reload=False)

if __name__ == "__main__":
    main()
