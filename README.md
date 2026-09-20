---
title: BASHA Security Platform
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 7860
pinned: false
---

# BASHA

Self-hosted, authorized security reconnaissance and low-impact assessment dashboard.

## Included
- FastAPI dashboard/API, PostgreSQL and Redis/Celery
- Mandatory authorization confirmation and server-side scope checks
- Explicit subprocess allowlist and `shell=False`
- Passive/safe/extended profiles
- 75 Comprehensive recon & security tools: whois, dig, dnsx, massdns, dnsrecon, fierce, crtsh, shodan_osint, spiderfoot, theharvester, checkdmarc, spoofcheck, subfinder, assetfinder, sublist3r, findomain, altdns, amass, subzy, subjack, anew, httpx, httprobe, whatweb, wafw00f, cloud_enum, prowler, scoutsuite, gau, waybackurls, uro, unfurl, katana, hakrawler, kiterunner, graphql_cop, arjun, paramspider, qsreplace, kxss, ffuf, gobuster, feroxbuster, dirsearch, bypass403, gitdumper, gitleaks, trufflehog, linkfinder, secretfinder, retirejs, securityheaders, corsy, wpscan, nikto, sslscan, sslyze, openssl, testssl, sqlmap, ghauri, commix, crlfsuite, dalfox, jwt_tool, smuggler, ssrf_detector, nuclei, cve_auditor, masscan, rustscan, naabu, netcat, zmap, nmap
- Low request rate and configurable stage cooldown
- Pause/resume/stop
- Asset, DNS, HTTP, technology, URL, endpoint and finding storage
- Finding deduplication and `UNVERIFIED` status
- HTML/JSON/CSV reports and live scan telemetry
- Non-root containers, read-only API filesystem, dropped capabilities, no-new-privileges

## Safety boundary
BASHA does not implement brute-force authentication, credential attacks, destructive payloads, denial-of-service testing, persistence, credential/session theft, or automatic account takeover. Nuclei is limited by default to `misconfig, exposure, headers, tech-detect`.

Use only on assets you are explicitly authorized to assess. Automated detections are not proof of vulnerabilities; manually verify before reporting.

## Ubuntu deployment
```bash
sudo apt update
sudo apt install -y docker.io docker-compose-plugin
sudo systemctl enable --now docker
unzip BASHA-project.zip
cd BASHA
cp .env.example .env
nano .env
mkdir -p reports
docker compose up -d --build
docker compose exec api python -m app.bootstrap
docker compose ps
```
Open `http://VPS_IP:8080`.

## HTTPS
Set DNS and edit `Caddyfile`, then `docker compose --profile https up -d`.

## Backup
```bash
docker compose exec -T postgres pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" > basha-backup.sql
cat basha-backup.sql | docker compose exec -T postgres psql -U "$POSTGRES_USER" "$POSTGRES_DB"
```

## Tests
```bash
pytest -q
```
For end-to-end testing use OWASP Juice Shop, DVWA or WebGoat in an isolated lab.
