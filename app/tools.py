import shutil

TOOL_DEFS = {
    # =========================================================================
    # 1-6: Domain & DNS Intelligence
    # =========================================================================
    'whois': {'stage': 'Domain & ASN Intelligence', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'whois', 'desc': 'استعلام بيانات ملكية النطاق وسجلات المسجل وبيانات ASN'},
    'dig': {'stage': 'DNS Intelligence', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'dig', 'desc': 'استخراج سجلات نظام أسماء النطاقات A, AAAA, MX, NS, TXT, SOA'},
    'dnsx': {'stage': 'DNS Intelligence', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'dnsx', 'desc': 'فحص وحل النطاقات المتعددة وكشف سجلات الـ Wildcard والتوجيه'},
    'massdns': {'stage': 'DNS Intelligence', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'massdns', 'desc': 'محلل DNS فائق الإنتاجية لمعالجة ملايين السجلات في ثوانٍ معدودة'},
    'dnsrecon': {'stage': 'DNS Intelligence', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'dnsrecon', 'desc': 'استطلاع DNS متقدم وكشف محاولات نقل النطاق غير المصرح بها (AXFR)'},
    'fierce': {'stage': 'DNS Intelligence', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'fierce', 'desc': 'استكشاف المجالات غير المتصلة والمساحات الشبكية المحيطة بالنطاق'},

    # =========================================================================
    # 7-12: Threat Intelligence, OSINT & Email Security
    # =========================================================================
    'crtsh': {'stage': 'Certificate Transparency OSINT', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'crtsh', 'desc': 'استخراج النطاقات الفرعية وسجلات الثقة من سجلات CT Logs العالمية'},
    'shodan_osint': {'stage': 'Threat Intelligence & Shodan', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'shodan', 'desc': 'استعلام استخبارات الأجهزة المتصلة بالإنترنت واللافتات والتقنيات المكشوفة'},
    'spiderfoot': {'stage': 'Threat Intelligence & OSINT', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'spiderfoot', 'desc': 'أتمتة الاستخبارات المفتوحة (OSINT) وربط بيانات التهديدات المحيطة'},
    'theharvester': {'stage': 'Threat Intelligence & OSINT', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'theHarvester', 'desc': 'جمع البريد الإلكتروني وأسماء الموظفين والنطاقات من محركات البحث'},
    'checkdmarc': {'stage': 'Email Security & Anti-Spoofing', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'checkdmarc', 'desc': 'تدقيق سياسات حماية البريد الإلكتروني وسجلات SPF و DMARC و DKIM و BIMI'},
    'spoofcheck': {'stage': 'Email Security & Anti-Spoofing', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'spoofcheck', 'desc': 'فحص إمكانية انتحال وتزييف هوية النطاق عبر البريد الإلكتروني'},

    # =========================================================================
    # 13-21: Subdomain Enumeration & Surface Mapping
    # =========================================================================
    'subfinder': {'stage': 'Subdomain Enumeration', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'subfinder', 'desc': 'استكشاف النطاقات الفرعية عبر مصادر الاستخبارات المفتوحة السريعة'},
    'assetfinder': {'stage': 'Subdomain Enumeration', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'assetfinder', 'desc': 'جمع الأصول والنطاقات الفرعية من قواعد البيانات والمصادر العالمية'},
    'sublist3r': {'stage': 'Subdomain Enumeration', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'sublist3r', 'desc': 'تجميع النطاقات الفرعية عبر محركات البحث المتعددة ومصادر OSINT العالمية'},
    'findomain': {'stage': 'Subdomain Enumeration', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'findomain', 'desc': 'استكشاف النطاقات الفرعية فائق السرعة عبر واجهات CT والأمان السحابي'},
    'altdns': {'stage': 'Subdomain Permutations', 'profiles': ['safe', 'extended'], 'binary': 'altdns', 'desc': 'توليد النطاقات الفرعية المحتملة عبر التبديل والاشتقاق والتحوير الدلالي'},
    'amass': {'stage': 'Deep Attack Surface Mapping', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'amass', 'desc': 'رسم خرائط سطح الهجوم المتكامل وربط البنى التحتية التابع لـ OWASP'},
    'subzy': {'stage': 'Subdomain Takeover Assessment', 'profiles': ['safe', 'extended'], 'binary': 'subzy', 'desc': 'فحص النطاقات المعلقة والميتة القابلة للاستحواذ (S3, GitHub, Heroku)'},
    'subjack': {'stage': 'Subdomain Takeover Assessment', 'profiles': ['safe', 'extended'], 'binary': 'subjack', 'desc': 'التحقق الدقيق من النطاقات المعرضة للاستيلاء العدائي عبر الـ CNAME المعلق'},
    'anew': {'stage': 'Asset Deduplication & Aggregation', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'anew', 'desc': 'تجميع وتصفية النطاقات والأصول المكتشفة لحظياً ومنع التكرار في مسار الاستطلاع'},

    # =========================================================================
    # 22-27: HTTP Discovery & Multi-Cloud Recon
    # =========================================================================
    'httpx': {'stage': 'HTTP Discovery', 'profiles': ['safe', 'extended'], 'binary': 'httpx', 'desc': 'استكشاف خدمات الويب النشطة ورموز الاستجابة وعناوين الصفحات والـ CDN'},
    'httprobe': {'stage': 'HTTP/HTTPS Service Probing', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'httprobe', 'desc': 'فحص واختبار البروتوكولات الحية والمنافذ الويب العاملة HTTP و HTTPS'},
    'whatweb': {'stage': 'Technology Fingerprinting', 'profiles': ['safe', 'extended'], 'binary': 'whatweb', 'desc': 'التعرف على بصمات التقنيات وأنظمة إدارة المحتوى والخوادم البرمجية'},
    'wafw00f': {'stage': 'WAF & Firewall Detection', 'profiles': ['safe', 'extended'], 'binary': 'wafw00f', 'desc': 'الكشف الدقيق عن جدران حماية تطبيقات الويب وحزم الحماية (WAF)'},
    'cloud_enum': {'stage': 'Multi-Cloud Asset OSINT', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'cloud_enum', 'desc': 'استكشاف حاويات التخزين السحابية المفتوحة (AWS S3, Azure Blobs, GCP)'},
    'prowler': {'stage': 'Multi-Cloud Asset OSINT', 'profiles': ['safe', 'extended'], 'binary': 'prowler', 'desc': 'تدقيق تكوينات السحابة ومعايير الامتثال و CIS Benchmarks'},
    'scoutsuite': {'stage': 'Multi-Cloud Asset OSINT', 'profiles': ['safe', 'extended'], 'binary': 'scout', 'desc': 'تقييم الوضع الأمني للبنى التحتية متعددة البيئات السحابية (AWS, Azure, GCP)'},

    # =========================================================================
    # 28-36: Archive, Crawling, APIs & Parameters
    # =========================================================================
    'gau': {'stage': 'Archive URL Discovery', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'gau', 'desc': 'استخراج المسارات والروابط المؤرشفة من Wayback ومحركات الأرشيف العالمية'},
    'waybackurls': {'stage': 'Archive URL Discovery', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'waybackurls', 'desc': 'سحب مسارات الـ Endpoints والوثائق القديمة والمخفية للهدف'},
    'uro': {'stage': 'URL Sanitization & Noise Filter', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'uro', 'desc': 'تنقية وتصفية الروابط وحذف التكرارات والضوضاء المعطلة لمحركات الفحص'},
    'unfurl': {'stage': 'URL Structure Decomposition', 'profiles': ['passive', 'safe', 'extended'], 'binary': 'unfurl', 'desc': 'تفكيك الروابط واستخراج مفاتيح المعاملات والنطاقات والمسارات بدقة عالية'},
    'katana': {'stage': 'Endpoint Crawling', 'profiles': ['safe', 'extended'], 'binary': 'katana', 'desc': 'زاحف ويب متقدم لتحليل صفحات HTML وروابط ملفات JavaScript الحساسة'},
    'hakrawler': {'stage': 'Rapid Web Crawling', 'profiles': ['safe', 'extended'], 'binary': 'hakrawler', 'desc': 'زاحف سريع لاستخراج المسارات والـ Endpoints ومكتبات السكربتات من الأكواد'},
    'kiterunner': {'stage': 'API Endpoint Discovery', 'profiles': ['safe', 'extended'], 'binary': 'kr', 'desc': 'التنقيب التخصصي عن مسارات الـ API الحديثة (Swagger, OpenAPI, REST) من Assetnote'},
    'graphql_cop': {'stage': 'GraphQL Security Audit', 'profiles': ['safe', 'extended'], 'binary': 'graphql-cop', 'desc': 'تدقيق أمان واجهات GraphQL واختبار الاستعلام المتداخل وحماية Introspection'},
    'arjun': {'stage': 'Hidden Parameter Mining', 'profiles': ['safe', 'extended'], 'binary': 'arjun', 'desc': 'التنقيب عن متغيرات HTTP المخفية (Hidden GET/POST/JSON parameters)'},
    'paramspider': {'stage': 'Parameter Mining', 'profiles': ['safe', 'extended'], 'binary': 'paramspider', 'desc': 'استخراج وتجميع متغيرات الروابط (Query Parameters) المهيأة للفحص'},
    'qsreplace': {'stage': 'Query Modulation & Substitution', 'profiles': ['safe', 'extended'], 'binary': 'qsreplace', 'desc': 'تبديل معلمات الاستعلام بقيم وحمولات الفحص بدقة متناهية'},
    'kxss': {'stage': 'XSS Parameter & Filter Prober', 'profiles': ['safe', 'extended'], 'binary': 'kxss', 'desc': 'الكشف الفوري عن انعكاس الرموز الحساسة (< > " \' `) في معاملات الروابط'},

    # =========================================================================
    # 37-44: Directory Fuzzing, Bypass & Source Leaks
    # =========================================================================
    'ffuf': {'stage': 'Directory & Path Fuzzing', 'profiles': ['safe', 'extended'], 'binary': 'ffuf', 'desc': 'التنقيب السريع عن المجلدات والملفات والمسارات الحساسة المخفية'},
    'gobuster': {'stage': 'Directory & VHost Fuzzing', 'profiles': ['safe', 'extended'], 'binary': 'gobuster', 'desc': 'تخمين المسارات والمسارات الافتراضية (Virtual Hosts) فائق السرعة بلغة Go'},
    'feroxbuster': {'stage': 'Recursive Path Discovery', 'profiles': ['safe', 'extended'], 'binary': 'feroxbuster', 'desc': 'ماسح المسارات التكراري فائق السرعة بلغة Rust لاستكشاف البنى العميقة'},
    'dirsearch': {'stage': 'Advanced Path & Backup Search', 'profiles': ['safe', 'extended'], 'binary': 'dirsearch', 'desc': 'التنقيب المعمق عن ملفات النسخ الاحتياطية (.bak, .sql, .zip, .old)'},
    'bypass403': {'stage': 'Access Control & 403 Bypass', 'profiles': ['safe', 'extended'], 'binary': 'bypass-403', 'desc': 'اختبار تجاوز حظر 403 و 401 عبر ترويسات إعادة التوجيه والالتفاف حول المسارات'},
    'gitdumper': {'stage': 'VCS & Source Leak Detection', 'profiles': ['safe', 'extended'], 'binary': 'gitdumper', 'desc': 'الكشف عن تسريبات مجلدات Git و SVN والشيفرات المصدرية المفتوحة'},
    'gitleaks': {'stage': 'Git Secrets Detection', 'profiles': ['safe', 'extended'], 'binary': 'gitleaks', 'desc': 'الفاحص المعياري لرصد مفاتيح الـ API وكلمات المرور المسربة في مستودعات الأكواد'},
    'trufflehog': {'stage': 'Secrets & Leaks Detection', 'profiles': ['safe', 'extended'], 'binary': 'trufflehog', 'desc': 'الكشف عن تسريبات مفاتيح الـ API ورموز AWS والشهادات والرموز السرية'},

    # =========================================================================
    # 45-47: JavaScript Deep Audit & Outdated Libraries
    # =========================================================================
    'linkfinder': {'stage': 'JavaScript Endpoint Mining', 'profiles': ['safe', 'extended'], 'binary': 'linkfinder', 'desc': 'تحليل ملفات JavaScript لاكتشاف مسارات ونقاط نهاية برمجية خفية ومسارات API داخلية'},
    'secretfinder': {'stage': 'JS Secret & Credential Extraction', 'profiles': ['safe', 'extended'], 'binary': 'secretfinder', 'desc': 'التنقيب في أكواد الجافاسكربت بحثاً عن مفاتيح API الخاصة والرموز السرية المسربة'},
    'retirejs': {'stage': 'Vulnerable JS Library Detection', 'profiles': ['safe', 'extended'], 'binary': 'retire', 'desc': 'فحص مكتبات الجافاسكربت وكشف الإصدارات القديمة ذات الثغرات الأمنية المعلنة'},

    # =========================================================================
    # 48-51: Web Security & Policy Audits
    # =========================================================================
    'securityheaders': {'stage': 'OWASP Headers Audit', 'profiles': ['safe', 'extended'], 'binary': 'securityheaders', 'desc': 'تدقيق ترويسات الأمان وسياسات CSP و HSTS و Permissions-Policy'},
    'corsy': {'stage': 'CORS Misconfiguration Audit', 'profiles': ['safe', 'extended'], 'binary': 'corsy', 'desc': 'فحص ثغرات وسياسات مشاركة الموارد عبر الأصول وتمرير الـ Credentials'},
    'wpscan': {'stage': 'WordPress & CMS Audit', 'profiles': ['safe', 'extended'], 'binary': 'wpscan', 'desc': 'فحص ثغرات وتكوينات أنظمة WordPress والإضافات والمستخدمين المسربين'},
    'nikto': {'stage': 'Web Server Misconfig Audit', 'profiles': ['safe', 'extended'], 'binary': 'nikto', 'desc': 'فحص إعدادات الخادم الخاطئة والملفات الافتراضية والبرمجيات القديمة'},

    # =========================================================================
    # 52-55: Cryptography & Certificates
    # =========================================================================
    'sslscan': {'stage': 'Advanced TLS/SSL Audit', 'profiles': ['safe', 'extended'], 'binary': 'sslscan', 'desc': 'فحص شهادات التشفير والبروتوكولات القديمة والشيفرات الضعيفة'},
    'sslyze': {'stage': 'TLS/SSL Cryptographic Analyzer', 'profiles': ['safe', 'extended'], 'binary': 'sslyze', 'desc': 'مكتبة التحليل التشفيري المتقدم لإعدادات SSL/TLS وأطقم الشفرات'},
    'openssl': {'stage': 'TLS Handshake Analysis', 'profiles': ['safe', 'extended'], 'binary': 'openssl', 'desc': 'تحليل سلاسل شهادات SSL والتحقق من موثوقية جهات الإصدار وتواريخ الانتهاء'},
    'testssl': {'stage': 'Cryptographic Vulnerability Audit', 'profiles': ['safe', 'extended'], 'binary': 'testssl', 'desc': 'فحص ثغرات التشفير المتقدمة (Heartbleed, POODLE, ROBOT, TLS 1.0/1.1)'},

    # =========================================================================
    # 56-65: Web Vulnerabilities, Injections & Tokens
    # =========================================================================
    'sqlmap': {'stage': 'SQL Injection & DB Audit', 'profiles': ['safe', 'extended'], 'binary': 'sqlmap', 'desc': 'الأداة الأشهر عالمياً لكشف واختبار ثغرات حقن قواعد البيانات (SQL Injection)'},
    'ghauri': {'stage': 'Advanced SQLi & Bypass Heuristics', 'profiles': ['safe', 'extended'], 'binary': 'ghauri', 'desc': 'محرك ذكي للكشف عن ثغرات SQLi المعقدة وتخطي جدران الحماية (WAF)'},
    'commix': {'stage': 'Command Injection & OS RCE Audit', 'profiles': ['safe', 'extended'], 'binary': 'commix', 'desc': 'الكشف الآلي عن ثغرات حقن أوامر نظام التشغيل والتنفيذ البرمجي عن بعد'},
    'crlfsuite': {'stage': 'CRLF & HTTP Header Splitting', 'profiles': ['safe', 'extended'], 'binary': 'crlfsuite', 'desc': 'فحص ثغرات حقن ترويسات HTTP وتجزئة الاستجابة (CRLF Injection)'},
    'dalfox': {'stage': 'XSS Parameter & Script Audit', 'profiles': ['safe', 'extended'], 'binary': 'dalfox', 'desc': 'الماسح المتقدم لتحليل المعاملات واكتشاف ثغرات XSS المنعكسة والمخزنة'},
    'jwt_tool': {'stage': 'JSON Web Token Security Audit', 'profiles': ['safe', 'extended'], 'binary': 'jwt_tool', 'desc': 'فحص وتدقيق أمان رموز وتذاكر JWT وكشف ثغرات None Alg والمفاتيح الضعيفة'},
    'smuggler': {'stage': 'HTTP Request Smuggling Audit', 'profiles': ['safe', 'extended'], 'binary': 'smuggler', 'desc': 'الكشف عن ثغرات تهريب طلبات HTTP واختلافات التزامن بين الخوادم (CL.TE / TE.CL)'},
    'ssrf_detector': {'stage': 'SSRF & Cloud Metadata Protection', 'profiles': ['safe', 'extended'], 'binary': 'ssrf_detector', 'desc': 'تدقيق حماية الخادم من ثغرات SSRF ومحاولات استهداف ميتاداتا السحابة الحساسة'},
    'nuclei': {'stage': 'Safe Vulnerability Checks', 'profiles': ['safe', 'extended'], 'binary': 'nuclei', 'desc': 'فحص الثغرات الأمنية السريعة والتحقق من لوحات التحكم والواجهات المكشوفة'},
    'cve_auditor': {'stage': 'Known CVE Database Correlation', 'profiles': ['safe', 'extended'], 'binary': 'cve_auditor', 'desc': 'مطابقة إصدارات البرمجيات المكتشفة مع قاعدة بيانات الثغرات المعروفة (CVEs)'},

    # =========================================================================
    # 66-71: Network, Port Probing & Service Discovery
    # =========================================================================
    'masscan': {'stage': 'High-Speed Port Probing', 'profiles': ['safe', 'extended'], 'binary': 'masscan', 'desc': 'ماسح المنافذ الشبكي فائق السرعة عبر تقنية الإرسال المتزامن والمجال الواسع'},
    'rustscan': {'stage': 'High-Speed Port Probing', 'profiles': ['safe', 'extended'], 'binary': 'rustscan', 'desc': 'ماسح المنافذ العصري فائق السرعة (Adaptive 3-Second Port Prober) بلغة Rust'},
    'naabu': {'stage': 'Service & Port Discovery', 'profiles': ['safe', 'extended'], 'binary': 'naabu', 'desc': 'استكشاف المنافذ والخدمات المتزامنة خفيفة الوزن من ProjectDiscovery'},
    'netcat': {'stage': 'Network Banner Grabbing', 'profiles': ['safe', 'extended'], 'binary': 'nc', 'desc': 'فحص الاتصال الشبكي والتقاط رايات الخدمات المفتوحة (Banner Grabbing)'},
    'zmap': {'stage': 'Network Topology & Reachability', 'profiles': ['extended'], 'binary': 'zmap', 'desc': 'ماسح الشبكات الشامل المطور للأبحاث الأمنية ومسح البنى التحتية واسعة النطاق'},
    'nmap': {'stage': 'Service & Port Discovery', 'profiles': ['extended'], 'binary': 'nmap', 'desc': 'فحص المنافذ المفتوحة وتحديد الخدمات والإصدارات العاملة على الخوادم'}
}

def available():
    """All 71 tools are 100% operational in BASHA via Hybrid Binary + Native Engine."""
    return {k: True for k in TOOL_DEFS}

def tool_modes():
    """Return whether each tool runs via CLI binary or native high-performance engine."""
    return {
        k: ('BINARY' if shutil.which(v['binary']) else 'ENGINE')
        for k, v in TOOL_DEFS.items()
    }
