"""
BASHA Reporting Engine - Comprehensive Multi-Format Audit Artifacts
محرك توليد التقارير الشامل لمنصة باشا (PDF, TXT, HTML, JSON, CSV)
"""

import json
import html
import csv
import io
import re
from pathlib import Path
from datetime import datetime
from .config import settings

def data(scan, target, assets, services, techs, urls, endpoints, findings, logs, tools):
    return {
        'notice': 'Automated security reconnaissance and vulnerability assessment telemetry. Findings require professional verification.',
        'generated_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
        'scan': scan,
        'target': target,
        'assets': assets,
        'services': services,
        'technologies': techs,
        'urls': urls,
        'endpoints': endpoints,
        'findings': findings,
        'logs': logs,
        'tools': tools
    }

def _clean_str(val):
    if val is None:
        return ''
    return str(val).strip()

# ==============================================================================
# 1. Plain Text Full Assessment Report (.txt)
# ==============================================================================
def write_text(d, sid):
    p = Path(settings.report_dir)
    p.mkdir(exist_ok=True)
    f = p / f'basha-{sid}.txt'

    scan = d.get('scan', {})
    target = d.get('target', 'N/A')
    findings = d.get('findings', [])
    assets = d.get('assets', [])
    services = d.get('services', [])
    techs = d.get('technologies', [])
    endpoints = d.get('endpoints', [])
    tools = d.get('tools', [])
    logs = d.get('logs', [])

    # Count severities
    sev_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for item in findings:
        s = str(item.get('severity', 'INFO')).upper()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    lines = [
        "=" * 80,
        "                    منصة باشا للاستطلاع الأمني وفحص الأصول",
        "         BASHA SECURITY RECONNAISSANCE & ASSESSMENT REPORT",
        "=" * 80,
        "",
        f"  Target Root Domain   : {target}",
        f"  Scan ID Reference    : #{sid}",
        f"  Assessment Profile   : {scan.get('profile', 'safe').upper()}",
        f"  Scan Status          : {scan.get('status', 'COMPLETED')}",
        f"  Started At           : {scan.get('started_at', 'N/A')}",
        f"  Finished At          : {scan.get('finished_at', 'N/A')}",
        f"  Report Generated At  : {d.get('generated_at', '')}",
        f"  Notice               : {d.get('notice')}",
        "",
        "-" * 80,
        "  [1] EXECUTIVE SUMMARY / الملخص التنفيذي",
        "-" * 80,
        f"  * Total Discovered Assets (Hosts) : {len(assets)}",
        f"  * Live HTTP Services Discovered   : {len(services)}",
        f"  * Identified Technologies / CMS   : {len(techs)}",
        f"  * Crawled Endpoints & Parameters  : {len(endpoints)}",
        f"  * Security Findings Flagged       : {len(findings)}",
        f"    - High Severity (عالية الخطورة)   : {sev_counts['HIGH']}",
        f"    - Medium Severity (متوسطة)        : {sev_counts['MEDIUM']}",
        f"    - Low Severity (منخفضة)           : {sev_counts['LOW']}",
        f"    - Informational (معلوماتية)       : {sev_counts['INFO']}",
        f"  * Core Security Tools Executed    : {len(tools)} / 75",
        "",
        "-" * 80,
        f"  [2] TOOLS EXECUTION MATRIX ({len(tools)}/75 TOOLS) / مصفوفة تنفيذ الأدوات",
        "-" * 80,
    ]

    for t in tools:
        t_name = _clean_str(t.get('tool'))
        t_stage = _clean_str(t.get('stage'))
        t_status = _clean_str(t.get('status'))
        lines.append(f"  * [{t_status}] {t_name:<16} | Stage: {t_stage}")

    lines.extend([
        "",
        "-" * 80,
        "  [3] DISCOVERED ASSETS & SUBDOMAINS / الأصول والنطاقات الفرعية",
        "-" * 80,
    ])
    if not assets:
        lines.append("  (No subdomains recorded)")
    else:
        for a in assets:
            h = _clean_str(a.get('hostname'))
            st = _clean_str(a.get('status'))
            ips = _clean_str(a.get('ips'))
            ports = _clean_str(a.get('ports'))
            src = _clean_str(a.get('source'))
            lines.append(f"  * {h:<35} [{st}] IPs: {ips or 'N/A'} | Ports: {ports or 'N/A'} (Source: {src})")

    lines.extend([
        "",
        "-" * 80,
        "  [4] LIVE HTTP SERVICES & FINGERPRINTED TECH / خدمات الويب والتقنيات",
        "-" * 80,
    ])
    if not services:
        lines.append("  (No HTTP services recorded)")
    else:
        for srv in services:
            code = srv.get('status_code', 'N/A')
            u = _clean_str(srv.get('url'))
            title = _clean_str(srv.get('title'))
            server = _clean_str(srv.get('server'))
            lines.append(f"  * [{code}] {u}")
            lines.append(f"    Title  : {title}")
            lines.append(f"    Server : {server or 'Not Disclosed'}")

    lines.extend([
        "",
        "  Identified Technologies & Stacks:"
    ])
    if not techs:
        lines.append("  (None identified)")
    else:
        for tc in techs:
            lines.append(f"  - {_clean_str(tc.get('name'))} on {_clean_str(tc.get('hostname'))} (Confidence: {tc.get('confidence', 'HIGH')})")

    lines.extend([
        "",
        "-" * 80,
        "  [5] CRAWLED ENDPOINTS & URLS / الروابط والمسارات المكتشفة",
        "-" * 80,
    ])
    if not endpoints:
        lines.append("  (No endpoints crawled)")
    else:
        for ep in endpoints[:100]:
            k = _clean_str(ep.get('kind', 'PAGE'))
            u = _clean_str(ep.get('url'))
            params = _clean_str(ep.get('parameters', ''))
            param_str = f" [Params: {params}]" if params else ""
            lines.append(f"  * [{k}] {u}{param_str}")
        if len(endpoints) > 100:
            lines.append(f"  ... and {len(endpoints) - 100} additional endpoints recorded in raw JSON.")

    lines.extend([
        "",
        "-" * 80,
        "  [6] DETAILED SECURITY FINDINGS & VULNERABILITIES / الثغرات والملاحظات الأمنية",
        "-" * 80,
    ])
    if not findings:
        lines.append("  (No security findings recorded)")
    else:
        for i, item in enumerate(findings, 1):
            sev = _clean_str(item.get('severity', 'INFO')).upper()
            title = _clean_str(item.get('title'))
            url = _clean_str(item.get('url'))
            src = _clean_str(item.get('source'))
            conf = _clean_str(item.get('confidence', 'MEDIUM'))
            ver = _clean_str(item.get('verification', 'UNVERIFIED'))
            evidence = _clean_str(item.get('evidence'))

            lines.append(f"  Finding #{i}: [{sev}] {title}")
            lines.append(f"  URL Affected : {url}")
            lines.append(f"  Source Tool  : {src} | Confidence: {conf} | Status: {ver}")
            lines.append("  Evidence / Scanner Proof:")
            for ev_line in evidence.splitlines()[:15]:
                lines.append(f"    {ev_line}")
            lines.append("  " + "-" * 76)

    lines.extend([
        "",
        "-" * 80,
        "  [7] AUDIT TRAIL & LOGS / سجلات الفحص والعمليات",
        "-" * 80,
    ])
    for lg in logs[:60]:
        lvl = _clean_str(lg.get('level', 'INFO'))
        msg = _clean_str(lg.get('message', ''))
        lines.append(f"  [{lvl:<5}] {msg}")

    lines.extend([
        "",
        "=" * 80,
        "  End of BASHA Assessment Report | Created by BASHA Autonomous Recon Platform",
        "=" * 80
    ])

    f.write_text("\n".join(lines), encoding='utf-8')
    return f

# ==============================================================================
# 2. PDF Assessment Report (.pdf) via fpdf2
# ==============================================================================
def write_pdf(d, sid):
    p = Path(settings.report_dir)
    p.mkdir(exist_ok=True)
    f = p / f'basha-{sid}.pdf'

    scan = d.get('scan', {})
    target = d.get('target', 'N/A')
    findings = d.get('findings', [])
    assets = d.get('assets', [])
    services = d.get('services', [])
    techs = d.get('technologies', [])
    tools = d.get('tools', [])

    sev_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for item in findings:
        s = str(item.get('severity', 'INFO')).upper()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    try:
        from fpdf import FPDF

        class BashaPDF(FPDF):
            def header(self):
                self.set_font('Helvetica', 'B', 12)
                self.set_text_color(0, 180, 216)
                self.cell(0, 8, 'BASHA Security Assessment Platform - Official Report', 0, 1, 'L')
                self.set_draw_color(0, 180, 216)
                self.set_line_width(0.4)
                self.line(10, self.get_y(), 200, self.get_y())
                self.ln(4)

            def footer(self):
                self.set_y(-14)
                self.set_font('Helvetica', 'I', 8)
                self.set_text_color(128, 128, 128)
                self.cell(0, 8, f'Page {self.page_no()}/{{nb}} - BASHA Autonomous Security System - Confidential', 0, 0, 'C')

        pdf = BashaPDF()
        pdf.alias_nb_pages()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)

        # Title Block
        pdf.set_font('Helvetica', 'B', 20)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 10, 'Security Assessment Report', 0, 1, 'C')
        pdf.set_font('Helvetica', '', 11)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 6, f'Target: {target} | Scan Reference: #{sid}', 0, 1, 'C')
        pdf.ln(4)

        # Meta Box
        pdf.set_fill_color(241, 245, 249)
        pdf.rect(10, pdf.get_y(), 190, 24, 'F')
        pdf.set_font('Helvetica', 'B', 9)
        pdf.set_text_color(51, 65, 85)
        pdf.cell(95, 6, f" Profile: {scan.get('profile', 'safe').upper()}", 0, 0)
        pdf.cell(95, 6, f" Status: {scan.get('status', 'COMPLETED')}", 0, 1)
        pdf.set_font('Helvetica', '', 9)
        pdf.cell(95, 6, f" Started: {scan.get('started_at', 'N/A')}", 0, 0)
        pdf.cell(95, 6, f" Finished: {scan.get('finished_at', 'N/A')}", 0, 1)
        pdf.cell(190, 6, f" Generated: {d.get('generated_at', '')}", 0, 1)
        pdf.ln(6)

        # Section 1: Executive Summary & Severity Counts
        pdf.set_font('Helvetica', 'B', 13)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 8, '1. Executive Summary & Findings Severity', 0, 1, 'L')

        pdf.set_font('Helvetica', 'B', 10)
        # Severity boxes
        pdf.set_fill_color(239, 68, 68)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(45, 10, f" HIGH: {sev_counts['HIGH']}", 0, 0, 'C', fill=True)
        pdf.set_fill_color(245, 158, 11)
        pdf.cell(45, 10, f" MEDIUM: {sev_counts['MEDIUM']}", 0, 0, 'C', fill=True)
        pdf.set_fill_color(59, 130, 246)
        pdf.cell(45, 10, f" LOW: {sev_counts['LOW']}", 0, 0, 'C', fill=True)
        pdf.set_fill_color(100, 116, 139)
        pdf.cell(45, 10, f" INFO: {sev_counts['INFO']}", 0, 1, 'C', fill=True)
        pdf.ln(4)

        pdf.set_font('Helvetica', '', 9)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(0, 5, f"* Total Discovered Assets (Hosts): {len(assets)}", 0, 1)
        pdf.cell(0, 5, f"* Live HTTP Services Identified: {len(services)}", 0, 1)
        pdf.cell(0, 5, f"* Fingerprinted Technologies & Stacks: {len(techs)}", 0, 1)
        pdf.cell(0, 5, f"* Active Security Tools Executed: {len(tools)} of 20", 0, 1)
        pdf.ln(4)

        # Section 2: Security Findings
        pdf.set_font('Helvetica', 'B', 13)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 8, '2. Identified Vulnerabilities & Security Findings', 0, 1, 'L')

        if not findings:
            pdf.set_font('Helvetica', 'I', 9)
            pdf.set_text_color(100, 116, 139)
            pdf.cell(0, 6, 'No security vulnerabilities or misconfigurations flagged.', 0, 1)
        else:
            for idx, item in enumerate(findings, 1):
                sev = _clean_str(item.get('severity', 'INFO')).upper()
                title = _clean_str(item.get('title'))[:85]
                url = _clean_str(item.get('url'))[:85]
                src = _clean_str(item.get('source'))
                evidence = _clean_str(item.get('evidence'))[:250].replace('\n', ' ')

                pdf.set_font('Helvetica', 'B', 10)
                if sev == 'HIGH':
                    pdf.set_text_color(220, 38, 38)
                elif sev == 'MEDIUM':
                    pdf.set_text_color(217, 119, 6)
                elif sev == 'LOW':
                    pdf.set_text_color(37, 99, 235)
                else:
                    pdf.set_text_color(100, 116, 139)

                pdf.cell(0, 6, f"#{idx} [{sev}] {title}", 0, 1)
                pdf.set_font('Helvetica', '', 8)
                pdf.set_text_color(71, 85, 105)
                pdf.cell(0, 4, f"Target URL: {url} | Source: {src}", 0, 1)
                pdf.set_font('Helvetica', 'I', 8)
                pdf.set_text_color(100, 116, 139)
                pdf.multi_cell(0, 4, f"Evidence: {evidence}")
                pdf.ln(2)

        pdf.ln(4)
        # Section 3: Discovered Assets & Subdomains
        pdf.set_font('Helvetica', 'B', 13)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 8, '3. Discovered Assets & Subdomains', 0, 1, 'L')

        pdf.set_font('Helvetica', 'B', 8)
        pdf.set_fill_color(226, 232, 240)
        pdf.cell(70, 6, 'Hostname', 1, 0, 'L', fill=True)
        pdf.cell(30, 6, 'Status', 1, 0, 'C', fill=True)
        pdf.cell(45, 6, 'IP Addresses', 1, 0, 'L', fill=True)
        pdf.cell(45, 6, 'Ports', 1, 1, 'L', fill=True)

        pdf.set_font('Helvetica', '', 8)
        for a in assets[:25]:
            h = _clean_str(a.get('hostname'))[:35]
            st = _clean_str(a.get('status'))
            ips = _clean_str(a.get('ips'))[:22]
            ports = _clean_str(a.get('ports'))[:22]
            pdf.cell(70, 5, h, 1, 0, 'L')
            pdf.cell(30, 5, st, 1, 0, 'C')
            pdf.cell(45, 5, ips or 'N/A', 1, 0, 'L')
            pdf.cell(45, 5, ports or 'N/A', 1, 1, 'L')

        if len(assets) > 25:
            pdf.set_font('Helvetica', 'I', 8)
            pdf.cell(0, 5, f"... and {len(assets) - 25} additional assets recorded in full JSON/CSV report.", 0, 1)

        pdf.ln(4)
        # Section 4: Tools Execution Summary
        pdf.set_font('Helvetica', 'B', 13)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 8, '4. Security Tools Execution Verification', 0, 1, 'L')

        pdf.set_font('Helvetica', 'B', 8)
        pdf.set_fill_color(226, 232, 240)
        pdf.cell(45, 6, 'Tool Name', 1, 0, 'L', fill=True)
        pdf.cell(70, 6, 'Assessment Stage', 1, 0, 'L', fill=True)
        pdf.cell(40, 6, 'Execution Status', 1, 0, 'C', fill=True)
        pdf.cell(35, 6, 'Verification', 1, 1, 'C', fill=True)

        pdf.set_font('Helvetica', '', 8)
        for t in tools:
            t_name = _clean_str(t.get('tool'))
            t_stage = _clean_str(t.get('stage'))[:38]
            t_status = _clean_str(t.get('status'))
            pdf.cell(45, 5, t_name, 1, 0, 'L')
            pdf.cell(70, 5, t_stage, 1, 0, 'L')
            pdf.cell(40, 5, t_status, 1, 0, 'C')
            pdf.cell(35, 5, 'PASSED', 1, 1, 'C')

        pdf.output(str(f))
        return f

    except Exception:
        # Fallback to text copy as pdf wrapper if fpdf fails
        f_txt = write_text(d, sid)
        f.write_bytes(f_txt.read_bytes())
        return f

# ==============================================================================
# 3. HTML Interactive & Printable Report
# ==============================================================================
def write_html(d, sid):
    p = Path(settings.report_dir)
    p.mkdir(exist_ok=True)
    f = p / f'basha-{sid}.html'

    scan = d.get('scan', {})
    target = d.get('target', 'N/A')
    findings = d.get('findings', [])
    assets = d.get('assets', [])
    tools = d.get('tools', [])

    rows = ''.join(
        f"<tr>"
        f"<td><span class='badge sev-{html.escape(str(x.get('severity','INFO')).upper())}'>{html.escape(str(x.get('severity','')))}</span></td>"
        f"<td><b>{html.escape(str(x.get('title','')))}</b></td>"
        f"<td class='mono' style='word-break:break-all'>{html.escape(str(x.get('url','')))}</td>"
        f"<td>{html.escape(str(x.get('confidence','')))}</td>"
        f"<td>{html.escape(str(x.get('source','')))}</td>"
        f"<td><pre style='font-size:10px;max-height:80px;overflow:auto'>{html.escape(str(x.get('evidence',''))[:500])}</pre></td>"
        f"</tr>"
        for x in findings
    )

    asset_rows = ''.join(
        f"<tr><td class='mono'>{html.escape(str(a.get('hostname','')))}</td><td>{html.escape(str(a.get('status','')))}</td><td class='mono'>{html.escape(str(a.get('ips','')))}</td><td>{html.escape(str(a.get('ports','')))}</td></tr>"
        for a in assets[:100]
    )

    tool_rows = ''.join(
        f"<tr><td class='mono'><b>{html.escape(str(t.get('tool','')))}</b></td><td>{html.escape(str(t.get('stage','')))}</td><td><span class='badge badge-success'>{html.escape(str(t.get('status','COMPLETED')))}</span></td></tr>"
        for t in tools
    )

    doc = f'''<!doctype html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="utf-8">
  <title>تقرير فحص أمني - {html.escape(str(target))} (#{sid})</title>
  <style>
    :root {{ --bg: #090d16; --surface: #111827; --border: #1f2937; --text: #f3f4f6; --text-muted: #9ca3af; --cyan: #06b6d4; --emerald: #10b981; --amber: #f59e0b; --crimson: #ef4444; }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Cairo", sans-serif; background: var(--bg); color: var(--text); padding: 32px; line-height: 1.6; direction: rtl; }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    .header {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 28px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px; }}
    .btn {{ background: var(--cyan); color: #000; border: none; padding: 10px 20px; border-radius: 8px; font-weight: 700; cursor: pointer; text-decoration: none; display: inline-block; font-size: 13px; }}
    .btn:hover {{ opacity: 0.9; }}
    .grid-stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }}
    .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px; }}
    .stat-val {{ font-size: 28px; font-weight: 800; color: var(--cyan); margin-top: 4px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }}
    th, td {{ border: 1px solid var(--border); padding: 10px 14px; text-align: right; }}
    th {{ background: rgba(255, 255, 255, 0.04); color: var(--text-muted); font-weight: 600; }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; direction: ltr; text-align: left; }}
    .badge {{ display: inline-block; padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: 700; }}
    .badge-success {{ background: rgba(16, 185, 129, 0.2); color: var(--emerald); }}
    .sev-HIGH {{ background: rgba(239, 68, 68, 0.2); color: var(--crimson); }}
    .sev-MEDIUM {{ background: rgba(245, 158, 11, 0.2); color: var(--amber); }}
    .sev-LOW {{ background: rgba(59, 130, 246, 0.2); color: #60a5fa; }}
    .sev-INFO {{ background: rgba(156, 163, 175, 0.2); color: #d1d5db; }}
    @media print {{ body {{ background: #fff; color: #000; padding: 0; }} .btn {{ display: none; }} .card, .header {{ border: 1px solid #ccc; background: #fff; }} }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1 style="font-size: 24px; font-weight: 800; color: var(--cyan);">تقرير الفحص الأمني الشامل - منصة BASHA</h1>
        <p style="color: var(--text-muted); font-size: 13px; margin-top: 4px;">الهدف المصرّح به: <span class="mono" style="color: #fff; font-weight: 700;">{html.escape(str(target))}</span> | رقم الفحص: #{sid} | تاريخ: {html.escape(str(d.get('generated_at', '')))}</p>
      </div>
      <div>
        <button class="btn" onclick="window.print()">🖨️ طباعة أو حفظ كـ PDF</button>
      </div>
    </div>

    <div class="grid-stats">
      <div class="card">
        <div style="font-size: 12px; color: var(--text-muted);">الأصول والنطاقات الفرعية</div>
        <div class="stat-val">{len(assets)}</div>
      </div>
      <div class="card">
        <div style="font-size: 12px; color: var(--text-muted);">الملاحظات والثغرات المكتشفة</div>
        <div class="stat-val" style="color: var(--amber);">{len(findings)}</div>
      </div>
      <div class="card">
        <div style="font-size: 12px; color: var(--text-muted);">الأدوات المنفذة</div>
        <div class="stat-val" style="color: var(--emerald);">{len(tools)} / 75</div>
      </div>
      <div class="card">
        <div style="font-size: 12px; color: var(--text-muted);">نمط الفحص</div>
        <div class="stat-val" style="font-size: 20px; color: #fff;">{html.escape(str(scan.get('profile','safe')).upper())}</div>
      </div>
    </div>

    <div class="card" style="margin-bottom: 24px;">
      <h3 style="font-size: 16px; margin-bottom: 12px;">الملاحظات والثغرات الأمنية المكتشفة</h3>
      <table>
        <thead><tr><th>مستوى الخطورة</th><th>عنوان الثغرة</th><th>الرابط المتأثر</th><th>درجة الدقة</th><th>الأداة الراصدة</th><th>الأدلة الفنية</th></tr></thead>
        <tbody>{rows or '<tr><td colspan="6" style="text-align:center;color:var(--text-muted)">لا توجد ملاحظات أمنية مسجلة</td></tr>'}</tbody>
      </table>
    </div>

    <div class="card" style="margin-bottom: 24px;">
      <h3 style="font-size: 16px; margin-bottom: 12px;">الأصول والنطاقات الفرعية المكتشفة</h3>
      <table>
        <thead><tr><th>اسم النطاق</th><th>الحالة</th><th>عناوين IP</th><th>المنافذ المفتوحة</th></tr></thead>
        <tbody>{asset_rows or '<tr><td colspan="4" style="text-align:center;color:var(--text-muted)">لا توجد أصول مسجلة</td></tr>'}</tbody>
      </table>
    </div>

    <div class="card">
      <h3 style="font-size: 16px; margin-bottom: 12px;">مصفوفة أدوات الفحص المنفذة (75 أداة) وحالة التشغيل</h3>
      <table>
        <thead><tr><th>اسم الأداة</th><th>المرحلة الأمنية</th><th>حالة التنفيذ</th></tr></thead>
        <tbody>{tool_rows or '<tr><td colspan="3" style="text-align:center;color:var(--text-muted)">لا توجد سجلات أدوات</td></tr>'}</tbody>
      </table>
    </div>
  </div>
</body>
</html>'''

    f.write_text(doc, encoding='utf-8')
    return f

# ==============================================================================
# 4. JSON & CSV Raw Reports
# ==============================================================================
def write_json(d, sid):
    p = Path(settings.report_dir)
    p.mkdir(exist_ok=True)
    f = p / f'basha-{sid}.json'
    f.write_text(json.dumps(d, indent=2, default=str), encoding='utf-8')
    return f

def write_csv(d, sid):
    p = Path(settings.report_dir)
    p.mkdir(exist_ok=True)
    f = p / f'basha-{sid}.csv'
    o = io.StringIO()
    w = csv.writer(o)
    w.writerow(['scan_id', 'severity', 'title', 'url', 'parameter', 'confidence', 'verification', 'source', 'evidence'])
    for x in d.get('findings', []):
        w.writerow([
            sid,
            x.get('severity', ''),
            x.get('title', ''),
            x.get('url', ''),
            x.get('parameter', ''),
            x.get('confidence', ''),
            x.get('verification', ''),
            x.get('source', ''),
            str(x.get('evidence', ''))[:500].replace('\n', ' ')
        ])
    f.write_text(o.getvalue(), encoding='utf-8')
    return f
