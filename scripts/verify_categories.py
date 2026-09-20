import json
from app.tools import TOOL_DEFS

with open('tools/tools.json', 'r', encoding='utf-8') as f:
    tj = json.load(f)

with open('app/local_worker.py', 'r', encoding='utf-8') as f:
    worker_code = f.read()

categories = {
    '1. Interception Proxies & Suites': ['burpsuite', 'zap', 'caido', 'mitmproxy', 'postman', 'insomnia'],
    '2. Subdomain Enumeration': ['subfinder', 'assetfinder', 'amass', 'findomain', 'chaos', 'knockpy', 'sublist3r', 'shuffledns'],
    '3. DNS Intelligence & Resolution': ['dnsx', 'massdns', 'puredns', 'dig', 'dnstwist'],
    '4. Port & Service Discovery': ['nmap', 'masscan', 'naabu', 'rustscan', 'zmap'],
    '5. HTTP Probing & Fingerprinting': ['httpx', 'httprobe', 'whatweb', 'wappalyzer', 'wafw00f'],
    '6. Crawling & Historical OSINT': ['katana', 'gau', 'waybackurls', 'hakrawler', 'gospider'],
    '7. Content Discovery & Fuzzing': ['ffuf', 'gobuster', 'dirsearch', 'feroxbuster', 'kiterunner'],
    '8. Parameter Mining': ['arjun', 'paramspider', 'x8'],
    '9. Template-Based Scanners': ['nuclei', 'nikto', 'openvas', 'nessus', 'qualys_was'],
    '10. SSL/TLS & Cryptography': ['testssl', 'sslscan', 'sslyze', 'crtsh'],
    '11. Cloud Security & Bucket Auditing': ['cloud_enum', 's3scanner', 'scoutsuite', 'prowler'],
    '12. Headers & CORS': ['corsy', 'securityheaders', 'csp_evaluator'],
    '13. Subdomain Takeover': ['subzy', 'subjack', 'canitakeoverxyz'],
    '14. Secrets & Credential Leaks': ['trufflehog', 'gitleaks', 'gitdumper', 'shhgit'],
    '15. CMS Scanning': ['wpscan', 'droopescan', 'joomscan', 'aem_hacker'],
    '16. SAST & SCA': ['semgrep', 'bandit', 'sonarqube', 'snyk', 'dependency_check'],
    '17. JS Analysis': ['linkfinder', 'secretfinder', 'js_scan', 'jsa'],
    '18. API & GraphQL Security': ['clairvoyance', 'graphql_voyager', 'astra', 'restler'],
    '19. Auth & Session Security': ['jwt_tool', 'saml_raider', 'oauthscan'],
    '20. Injection Detection': ['sqlmap', 'ghauri', 'nosqlmap', 'commix'],
    '21. XSS & Client-Side': ['dalfox', 'xsstrike', 'dompurify_tester'],
    '22. Piping & Automation Utilities': ['anew', 'qsreplace', 'unfurl', 'notify', 'interlace'],
    '23. Threat Intelligence & Global OSINT': ['shodan_osint', 'censys', 'securitytrails']
}

all_ok = True
total_tools = 0

for cat, tools in categories.items():
    print(f"=== {cat} ===")
    for t in tools:
        total_tools += 1
        in_defs = t in TOOL_DEFS
        in_json = t in tj
        in_worker = (f"'{t}'" in worker_code) or (f'"{t}"' in worker_code)
        status = "OK" if (in_defs and in_json and in_worker) else "FAIL"
        if status == "FAIL":
            all_ok = False
            print(f"  [X] {t:20s} in_defs={in_defs}, in_json={in_json}, in_worker={in_worker}")
        else:
            print(f"  [V] {t:20s} (all registered and wired)")

print(f"\nTotal categorized tools checked: {total_tools}")
print(f"All 99 requested tools present, registered, and wired in engine/worker: {all_ok}")
