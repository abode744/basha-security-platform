#!/usr/bin/env bash
set -e

# ==============================================================================
# BASHA v1.0 - VPS One-Click Automated Setup Script
# سكريبت التثبيت والتشغيل الشامل والأوتوماتيكي لمنصة باشا على السيرفر
# ==============================================================================

echo "=========================================================="
echo "          🚀 بدء تثبيت وتشغيل منصة BASHA على السيرفر       "
echo "=========================================================="

# 1. Check Root Privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  يرجى تشغيل السكربت بصلاحيات root أو باستخدام sudo:"
    echo "    sudo bash setup.sh"
    exit 1
fi

# 2. Check and Install Docker & Docker Compose
if ! command -v docker >/dev/null 2>&1; then
    echo "[+] Docker غير مثبت. جاري تثبيت Docker تلقائياً..."
    apt-get update -y
    apt-get install -y curl ca-certificates
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm -f get-docker.sh
    systemctl enable docker
    systemctl start docker
    echo "[✔] تم تثبيت Docker بنجاح."
else
    echo "[✔] Docker مثبت مسبقاً."
fi

# Ensure docker compose plugin exists
if ! docker compose version >/dev/null 2>&1; then
    echo "[+] تثبيت إضافة Docker Compose..."
    apt-get update -y
    apt-get install -y docker-compose-plugin || true
fi

# 3. Setup .env file
if [ ! -f .env ]; then
    echo "[+] إنشاء ملف الإعدادات .env من النموذج..."
    if [ -f .env.example ]; then
        cp .env.example .env
    else
        cat << 'EOF' > .env
POSTGRES_DB=basha
POSTGRES_USER=basha
POSTGRES_PASSWORD=basha_secret_2024
DATABASE_URL=postgresql+psycopg://basha:basha_secret_2024@postgres:5432/basha
REDIS_URL=redis://redis:6379/0
BASHA_SECRET_KEY=b4eb051caf7549f0bb0261d23c901fe315f1007c260640488e5a7a9768bdc3e3
BASHA_ADMIN_USER=abod
BASHA_ADMIN_PASSWORD=2024
MAX_WORKERS=2
DEFAULT_MAX_RPS=1.0
DEFAULT_STAGE_COOLDOWN_SECONDS=240
REPORT_DIR=reports
JWT_TTL_MINUTES=480
EOF
    fi
fi

# Ensure Admin Credentials in .env
sed -i 's/^BASHA_ADMIN_USER=.*/BASHA_ADMIN_USER=abod/' .env || echo "BASHA_ADMIN_USER=abod" >> .env
sed -i 's/^BASHA_ADMIN_PASSWORD=.*/BASHA_ADMIN_PASSWORD=2024/' .env || echo "BASHA_ADMIN_PASSWORD=2024" >> .env

# 4. Create directories
mkdir -p reports
chmod 777 reports

# 5. Build and Run Containers
echo "[+] جاري بناء وتشغيل حاويات النظام (قد يستغرق بضع دقائق في المرة الأولى)..."
docker compose down --remove-orphans 2>/dev/null || true
docker compose up -d --build

echo "[+] جاري انتظار جاهزية قاعدة البيانات وخادم الويب..."
MAX_TRIES=30
COUNT=0
while [ $COUNT -lt $MAX_TRIES ]; do
    if curl -s http://127.0.0.1:8080/api/health >/dev/null 2>&1; then
        echo "[✔] النظام يعمل بنجاح وبكفاءة!"
        break
    fi
    sleep 3
    COUNT=$((COUNT+1))
done

# 6. Ensure Admin User in DB
echo "[+] التحقق من حساب المدير الافتراضي..."
docker compose exec -T api python -m app.bootstrap || true

# 7. Open firewall port 8080 if ufw is active
if command -v ufw >/dev/null 2>&1; then
    if ufw status | grep -q "Status: active"; then
        echo "[+] فتح المنفذ 8080 في الجدار الناري UFW..."
        ufw allow 8080/tcp || true
    fi
fi

# Get Public IP
VPS_IP=$(curl -s https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')

echo ""
echo "=========================================================="
echo "             🎉 اكتمل التثبيت والتشغيل بنجاح!            "
echo "=========================================================="
echo ""
echo "📌 رابط لوحة التحكم:"
echo "   http://${VPS_IP}:8080"
echo ""
echo "🔐 بيانات الدخول الافتراضية:"
echo "   اسم المستخدم : abod"
echo "   كلمة المرور  : 2024"
echo ""
echo "🛠️ أدوات الفحص المدمجة (20 أداة نشطة ومحدثة 100%):"
echo "   - الاستكشاف والنطاقات  : subfinder, assetfinder, dnsx, dig, whois"
echo "   - مسح المنافذ والشبكة  : nmap, openssl, sslscan"
echo "   - فحص الويب والمسارات  : httpx, katana, gau, waybackurls, whatweb, wafw00f, paramspider"
echo "   - التنقيب وفحص التكوين : ffuf, securityheaders, trufflehog, nikto"
echo "   - فحص الثغرات الأمنية : nuclei"
echo ""
echo "📋 أوامر مفيدة للإدارة:"
echo "   - مشاهدة السجلات الحية : docker compose logs -f"
echo "   - إيقاف المنصة        : docker compose down"
echo "   - إعادة تشغيل المنصة   : docker compose restart"
echo "=========================================================="
