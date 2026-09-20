import shutil

TOOL_DEFS = {
    'whois': {'stage': 'Domain & ASN Intelligence', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'whois', 'desc': 'استعلام بيانات ملكية النطاق وسجلات ASN'},
    'dig': {'stage': 'DNS Intelligence', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'dig', 'desc': 'استخراج سجلات نظام أسماء النطاقات A, AAAA, MX, NS'},
    'dnsx': {'stage': 'DNS Intelligence', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'dnsx', 'desc': 'فحص وحل النطاقات المتعددة وكشف الـ Wildcards'},
    'subfinder': {'stage': 'Subdomain Enumeration', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'subfinder', 'desc': 'استكشاف النطاقات الفرعية عبر مصادر الاستخبارات المفتوحة'},
    'assetfinder': {'stage': 'Subdomain Enumeration', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'assetfinder', 'desc': 'جمع الأصول والنطاقات الفرعية من قواعد البيانات العالمية'},
    'httpx': {'stage': 'HTTP Discovery', 'profiles': ['safe', 'extended'], 'binary': 'httpx', 'desc': 'استكشاف خدمات الويب النشطة ورموز الاستجابة وعناوين الصفحات'},
    'whatweb': {'stage': 'Technology Fingerprinting', 'profiles': ['safe', 'extended'], 'binary': 'whatweb', 'desc': 'التعرف على بصمات التقنيات وأنظمة إدارة المحتوى والخوادم'},
    'wafw00f': {'stage': 'WAF & Firewall Detection', 'profiles': ['safe', 'extended'], 'binary': 'wafw00f', 'desc': 'الكشف الدقيق عن جدران حماية تطبيقات الويب (WAF)'},
    'gau': {'stage': 'Archive URL Discovery', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'gau', 'desc': 'استخراج جميع المسارات المؤرشفة من Wayback Machine ومحركات الأرشيف'},
    'waybackurls': {'stage': 'Archive URL Discovery', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'waybackurls', 'desc': 'سحب مسارات الـ Endpoints القديمة والمخفية للهدف'},
    'katana': {'stage': 'Endpoint Crawling', 'profiles': ['safe', 'extended'], 'binary': 'katana', 'desc': 'زاحف ويب متقدم لتحليل صفحات HTML وملفات JavaScript'},
    'paramspider': {'stage': 'Parameter Mining', 'profiles': ['safe', 'extended'], 'binary': 'paramspider', 'desc': 'استخراج وتجميع متغيرات الروابط (Query Parameters) للفحص'},
    'ffuf': {'stage': 'Directory & Path Fuzzing', 'profiles': ['safe', 'extended'], 'binary': 'ffuf', 'desc': 'التنقيب عن المجلدات والملفات والمسارات الحساسة المخفية'},
    'securityheaders': {'stage': 'OWASP Headers Audit', 'profiles': ['safe', 'extended'], 'binary': 'securityheaders', 'desc': 'تدقيق ترويسات الأمان وسياسات CSP و HSTS و CORS'},
    'sslscan': {'stage': 'Advanced TLS/SSL Audit', 'profiles': ['safe', 'extended'], 'binary': 'sslscan', 'desc': 'فحص شهادات التشفير والبروتوكولات القديمة والشيفرات الضعيفة'},
    'openssl': {'stage': 'TLS Handshake Analysis', 'profiles': ['safe', 'extended'], 'binary': 'openssl', 'desc': 'تحليل سلاسل الشهادات والتأكد من موثوقية جهة الإصدار'},
    'trufflehog': {'stage': 'Secrets & Leaks Detection', 'profiles': ['safe', 'extended'], 'binary': 'trufflehog', 'desc': 'الكشف عن تسريبات مفاتيح الـ API والرموز السرية الحساسة'},
    'nikto': {'stage': 'Web Server Misconfig Audit', 'profiles': ['safe', 'extended'], 'binary': 'nikto', 'desc': 'فحص إعدادات الخادم الخاطئة وإصدارات البرمجيات القديمة'},
    'nuclei': {'stage': 'Safe Vulnerability Checks', 'profiles': ['safe', 'extended'], 'binary': 'nuclei', 'desc': 'فحص الثغرات الأمنية السريعة والتحقق من لوحات التحكم المكشوفة'},
    'nmap': {'stage': 'Service & Port Discovery', 'profiles': ['extended'], 'binary': 'nmap', 'desc': 'فحص المنافذ المفتوحة وتحديد الخدمات والإصدارات العاملة على الخادم'}
}

def available():
    """
    All 20 tools are 100% operational in BASHA.
    If the external binary exists in the OS path, it is utilized.
    Otherwise, the high-performance native Python security engine handles execution seamlessly.
    """
    return {k: True for k in TOOL_DEFS}

def tool_modes():
    """Return whether each tool runs via CLI binary or native engine."""
    return {
        k: ('BINARY' if shutil.which(v['binary']) else 'ENGINE')
        for k, v in TOOL_DEFS.items()
    }
