# دليل تشغيل منصة BASHA على خادم VPS

تم تجهيز هذا المشروع ليعمل فوراً وبشكل تلقائي على خوادم Linux (Ubuntu / Debian).

---

## 1. متطلبات الخادم (VPS Requirements)

- **نظام التشغيل الموصى به:** Ubuntu 22.04 LTS أو Ubuntu 24.04 LTS (أو Debian 11/12).
- **المعالج (CPU):** معالجان (2 vCPU) أو أكثر (لأن أدوات الاستطلاع والفحص مثل subfinder و nuclei تعمل بتعدد الخيوط).
- **الذاكرة العشوائية (RAM):** 
  - يفضل **4 جيجابايت RAM** لتفادي أي ضغط أثناء الفحص.
  - إذا كان السيرفر 2 جيجابايت فقط، يفضل تفعيل 2 جيجابايت Swap memory.
- **التخزين (Disk):** 20 - 30 جيجابايت SSD.
- **المنافذ المطلوب فتحها (Ports):**
  - منفذ `22` (SSH للاتصال بالسيرفر).
  - منفذ `8080` (لوحة تحكم BASHA عبر HTTP).
  - منفذ `80` و `443` (اختياري، في حال أردت ربط دومين وتفعيل HTTPS).

---

## 2. كيفية نقل الملفات إلى الـ VPS

### الطريقة الأولى: عبر برنامج WinSCP أو FileZilla (الأسهل)
1. افتح برنامج **WinSCP** أو **FileZilla**.
2. اتصل بالسيرفر باستخدام بروتوكول **SFTP** وعبر IP السيرفر واسم المستخدم (`root`) وكلمة المرور.
3. قم بسحب وإسقاط مجلد `BASHA-v1-complete` إلى المسار الرئيسي على السيرفر (مثلاً داخل `/root/basha`).

### الطريقة الثانية: ضغط المجلد ونقله عبر سطر الأوامر (SCP)
من جهازك المحلي (PowerShell):
```powershell
tar -czvf basha.tar.gz -C "c:\Users\bwdy5\Downloads\BASHA-v1-complete" .
scp basha.tar.gz root@YOUR_SERVER_IP:/root/
```
وعلى السيرفر عبر SSH:
```bash
mkdir -p /root/basha && cd /root/basha
tar -xzvf /root/basha.tar.gz
```

---

## 3. التشغيل السريع بضغطة زر واحدة (Automated Setup)

داخل مجلد المشروع على الـ VPS، قمنا بإنشاء سكربت تثبيت أوتوماتيكي يقوم بكل شيء:
```bash
cd /root/basha
chmod +x setup.sh
sudo bash setup.sh
```

**ماذا سيفعل هذا السكربت تلقائياً؟**
1. تثبيت Docker و Docker Compose في حال لم يكونا مثبتين.
2. التحقق من ملف الإعدادات `.env` وتوليد مفاتيح وكلمات مرور مشفرة وآمنة.
3. إنشاء مجلد التقارير `reports` وضبط الصلاحيات الصحيحة.
4. بناء الحاويات وتشغيلها في الخلفية (`docker compose up -d --build`).
5. تهيئة قاعدة البيانات وإنشاء حساب المدير (Admin).
6. فتح المنفذ في الجدار الناري وعرض رابط الدخول وبيانات الحساب على الشاشة.

---

## 4. بيانات تسجيل الدخول الافتراضية

الملف `.env` تم تجهيزه بالفعل، وبيانات الدخول الحالية هي:
- **رابط اللوحة:** `http://YOUR_VPS_IP:8080`
- **اسم المستخدم (Username):** `abod`
- **كلمة المرور (Password):** `2024`

*(يمكنك تغيير كلمة المرور في أي وقت من خلال تعديل ملف `.env`)*

---

## 5. تشغيل HTTPS مع دومين خاص (اختياري)

إذا كنت تملك اسم نطاق وتريد تفعيل شهادة أمان SSL مجانية:
1. وجّه الـ DNS للدومين إلى عنوان IP السيرفر (A Record).
2. افتح ملف `Caddyfile`:
   ```bash
   nano Caddyfile
   ```
   واستبدل `basha.example.com` باسم النطاق الخاص بك، ثم احفظ الملف.
3. شغّل خدمة الـ HTTPS عبر الأمر:
   ```bash
   docker compose --profile https up -d
   ```
   وسيقوم خادم Caddy بإصدار وتجديد شهادة SSL تلقائياً من Let's Encrypt.

---

## 6. أوامر مهمة لإدارة النظام على السيرفر

- **عرض سجلات التشغيل (Live Logs):**
  ```bash
  docker compose logs -f
  ```
- **إيقاف الخدمات:**
  ```bash
  docker compose down
  ```
- **إعادة تشغيل الخدمات:**
  ```bash
  docker compose restart
  ```
- **أخذ نسخة احتياطية من قاعدة البيانات (Backup):**
  ```bash
  docker compose exec -T postgres pg_dump -U basha basha > basha-backup.sql
  ```
- **استعادة النسخة الاحتياطية (Restore):**
  ```bash
  cat basha-backup.sql | docker compose exec -T postgres psql -U basha basha
  ```
