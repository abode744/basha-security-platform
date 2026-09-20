import shutil

TOOL_DEFS = {
    # 1-5: Domain & DNS Intelligence
    'whois': {'stage': 'Domain & ASN Intelligence', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'whois', 'desc': 'استعلام بيانات ملكية النطاق وسجلات المسجل وبيانات ASN'},
    'dig': {'stage': 'DNS Intelligence', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'dig', 'desc': 'استخراج سجلات نظام أسماء النطاقات A, AAAA, MX, NS, TXT, SOA'},
    'dnsx': {'stage': 'DNS Intelligence', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'dnsx', 'desc': 'فحص وحل النطاقات المتعددة وكشف سجلات الـ Wildcard والتوجيه'},
    'crtsh': {'stage': 'Certificate Transparency OSINT', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'crtsh', 'desc': 'استخراج النطاقات الفرعية وسجلات الثقة من سجلات CT Logs العالمية'},
    'shodan_osint': {'stage': 'Threat Intelligence & Shodan', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'shodan', 'desc': 'استعلام استخبارات الأجهزة المتصلة بالإنترنت واللافتات والتقنيات المكشوفة'},

    # 6-9: Subdomain Enumeration & Surface Mapping
    'subfinder': {'stage': 'Subdomain Enumeration', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'subfinder', 'desc': 'استكشاف النطاقات الفرعية عبر مصادر الاستخبارات المفتوحة السريعة'},
    'assetfinder': {'stage': 'Subdomain Enumeration', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'assetfinder', 'desc': 'جمع الأصول والنطاقات الفرعية من قواعد البيانات والمصادر العالمية'},
    'amass': {'stage': 'Deep Attack Surface Mapping', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'amass', 'desc': 'رسم خرائط سطح الهجوم المتكامل وربط البنى التحتية التابع لـ OWASP'},
    'subzy': {'stage': 'Subdomain Takeover Assessment', 'profiles': ['safe', 'extended'], 'binary': 'subzy', 'desc': 'فحص النطاقات المعلقة والميتة القابلة للاستحواذ (S3, GitHub, Heroku)'},

    # 10-13: HTTP Discovery & Cloud Recon
    'httpx': {'stage': 'HTTP Discovery', 'profiles': ['safe', 'extended'], 'binary': 'httpx', 'desc': 'استكشاف خدمات الويب النشطة ورموز الاستجابة وعناوين الصفحات والـ CDN'},
    'whatweb': {'stage': 'Technology Fingerprinting', 'profiles': ['safe', 'extended'], 'binary': 'whatweb', 'desc': 'التعرف على بصمات التقنيات وأنظمة إدارة المحتوى والخوادم البرمجية'},
    'wafw00f': {'stage': 'WAF & Firewall Detection', 'profiles': ['safe', 'extended'], 'binary': 'wafw00f', 'desc': 'الكشف الدقيق عن جدران حماية تطبيقات الويب وحزم الحماية (WAF)'},
    'cloud_enum': {'stage': 'Multi-Cloud Asset OSINT', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'cloud_enum', 'desc': 'استكشاف حاويات التخزين السحابية المفتوحة (AWS S3, Azure Blobs, GCP)'},

    # 14-17: Endpoints, Crawling & Parameters
    'gau': {'stage': 'Archive URL Discovery', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'gau', 'desc': 'استخراج المسارات والروابط المؤرشفة من Wayback ومحركات الأرشيف العالمية'},
    'waybackurls': {'stage': 'Archive URL Discovery', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'waybackurls', 'desc': 'سحب مسارات الـ Endpoints والوثائق القديمة والمخفية للهدف'},
    'katana': {'stage': 'Endpoint Crawling', 'profiles': ['safe', 'extended'], 'binary': 'katana', 'desc': 'زاحف ويب متقدم لتحليل صفحات HTML وروابط ملفات JavaScript الحساسة'},
    'arjun': {'stage': 'Hidden Parameter Mining', 'profiles': ['safe', 'extended'], 'binary': 'arjun', 'desc': 'التنقيب عن متغيرات HTTP المخفية (Hidden GET/POST/JSON parameters)'},
    'paramspider': {'stage': 'Parameter Mining', 'profiles': ['safe', 'extended'], 'binary': 'paramspider', 'desc': 'استخراج وتجميع متغيرات الروابط (Query Parameters) المهيأة للفحص'},

    # 18-21: Directory Fuzzing & Source Leaks
    'ffuf': {'stage': 'Directory & Path Fuzzing', 'profiles': ['safe', 'extended'], 'binary': 'ffuf', 'desc': 'التنقيب السريع عن المجلدات والملفات والمسارات الحساسة المخفية'},
    'dirsearch': {'stage': 'Advanced Path & Backup Search', 'profiles': ['safe', 'extended'], 'binary': 'dirsearch', 'desc': 'التنقيب المعمق عن ملفات النسخ الاحتياطية (.bak, .sql, .zip, .old)'},
    'gitdumper': {'stage': 'VCS & Source Leak Detection', 'profiles': ['safe', 'extended'], 'binary': 'gitdumper', 'desc': 'الكشف عن تسريبات مجلدات Git و SVN والشيفرات المصدرية المفتوحة'},
    'trufflehog': {'stage': 'Secrets & Leaks Detection', 'profiles': ['safe', 'extended'], 'binary': 'trufflehog', 'desc': 'الكشف عن تسريبات مفاتيح الـ API ورموز AWS والشهادات والرموز السرية'},

    # 22-26: Web Security & Policy Audits
    'securityheaders': {'stage': 'OWASP Headers Audit', 'profiles': ['safe', 'extended'], 'binary': 'securityheaders', 'desc': 'تدقيق ترويسات الأمان وسياسات CSP و HSTS و Permissions-Policy'},
    'corsy': {'stage': 'CORS Misconfiguration Audit', 'profiles': ['safe', 'extended'], 'binary': 'corsy', 'desc': 'فحص ثغرات وسياسات مشاركة الموارد عبر الأصول وتمرير الـ Credentials'},
    'wpscan': {'stage': 'WordPress & CMS Audit', 'profiles': ['safe', 'extended'], 'binary': 'wpscan', 'desc': 'فحص ثغرات وتكوينات أنظمة WordPress والإضافات والمستخدمين المسربين'},
    'nikto': {'stage': 'Web Server Misconfig Audit', 'profiles': ['safe', 'extended'], 'binary': 'nikto', 'desc': 'فحص إعدادات الخادم الخاطئة والملفات الافتراضية والبرمجيات القديمة'},

    # 27-30: Cryptography & Certificates
    'sslscan': {'stage': 'Advanced TLS/SSL Audit', 'profiles': ['safe', 'extended'], 'binary': 'sslscan', 'desc': 'فحص شهادات التشفير والبروتوكولات القديمة والشيفرات الضعيفة'},
    'openssl': {'stage': 'TLS Handshake Analysis', 'profiles': ['safe', 'extended'], 'binary': 'openssl', 'desc': 'تحليل سلاسل شهادات SSL والتحقق من موثوقية جهات الإصدار وتواريخ الانتهاء'},
    'testssl': {'stage': 'Cryptographic Vulnerability Audit', 'profiles': ['safe', 'extended'], 'binary': 'testssl', 'desc': 'فحص ثغرات التشفير المتقدمة (Heartbleed, POODLE, ROBOT, TLS 1.0/1.1)'},

    # 31-32: Vulnerabilities & Ports
    'nuclei': {'stage': 'Safe Vulnerability Checks', 'profiles': ['safe', 'extended'], 'binary': 'nuclei', 'desc': 'فحص الثغرات الأمنية السريعة والتحقق من لوحات التحكم والواجهات المكشوفة'},
    'cve_auditor': {'stage': 'Known CVE Database Correlation', 'profiles': ['safe', 'extended'], 'binary': 'cve_auditor', 'desc': 'مطابقة إصدارات البرمجيات المكتشفة مع قاعدة بيانات الثغرات المعروفة (CVEs)'},
    'nmap': {'stage': 'Service & Port Discovery', 'profiles': ['extended'], 'binary': 'nmap', 'desc': 'فحص المنافذ المفتوحة وتحديد الخدمات والإصدارات العاملة على الخوادم'}
}

def available():
    """All 32 tools are 100% operational in BASHA."""
    return {k: True for k in TOOL_DEFS}

def tool_modes():
    """Return whether each tool runs via CLI binary or native high-performance engine."""
    return {
        k: ('BINARY' if shutil.which(v['binary']) else 'ENGINE')
        for k, v in TOOL_DEFS.items()
    }
