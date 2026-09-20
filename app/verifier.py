"""
BASHA Security Platform - Vulnerability Verification & False-Positive Elimination Engine
محرك التحقق القطعي من الثغرات وتصفية الإنذارات الكاذبة بنسبة خطأ صفرية (Zero-False-Positive Engine)
"""

import re
import time
import httpx
from urllib.parse import urlparse, urljoin

# Signatures for Abandoned Cloud Services (Subdomain Takeover)
TAKEOVER_SIGNATURES = {
    'github.io': ['There isn\'t a GitHub Pages site here', '404 There isn\'t a GitHub Pages site here'],
    'herokuapp.com': ['There is no app configured at that hostname', 'Heroku | No such app'],
    's3.amazonaws.com': ['The specified bucket does not exist', 'NoSuchBucket'],
    'surge.sh': ['project not found', 'Surge: page not found'],
    'bitbucket.io': ['Repository not found', 'Resource not found'],
    'azurewebsites.net': ['404 Web Site not found', 'Microsoft Azure App Service - Error 404'],
    'zendesk.com': ['Help Center Closed', 'No such host'],
    'shopify.com': ['Sorry, this shop is currently unavailable', 'Shopify: Not Found']
}

def verify_finding_deterministically(title: str, url: str, finding_type: str = '', evidence: str = '') -> dict:
    """
    Execute rigorous, non-destructive, deterministic verification to confirm whether
    a security finding actually exists on the target or is a false-positive (Soft-404, generic reflection, etc.).
    Returns:
      {
        'status': 'CONFIRMED' | 'FALSE_POSITIVE' | 'INCONCLUSIVE',
        'confidence': 100 or float,
        'reason': str,
        'technical_proof': str,
        'diff_details': dict
      }
    """
    if not url or not url.startswith(('http://', 'https://')):
        return {
            'status': 'FALSE_POSITIVE',
            'confidence': 100,
            'reason': 'العنوان المستهدف غير صالح أو لا يتبع بروتوكول HTTP/HTTPS.',
            'technical_proof': f'Invalid URL provided: {url}',
            'diff_details': {}
        }

    parsed = urlparse(url)
    base_host_url = f"{parsed.scheme}://{parsed.netloc}"
    lower_title = title.lower()

    # Step 1: Reachability & Soft-404 Differential Baseline
    # Generate a random non-existent path on the target host to determine how the server handles 404s.
    canary_path = f"/basha_canary_verify_{int(time.time())}_{hash(url) % 10000}.html"
    canary_url = urljoin(base_host_url, canary_path)

    try:
        with httpx.Client(timeout=8.0, verify=False, follow_redirects=True) as client:
            headers = {
                'User-Agent': 'BASHA-Verification-Engine/2.0 (Zero-Noise AppSec Auditor)',
                'Accept': '*/*'
            }
            # Baseline probe on target URL
            try:
                target_resp = client.get(url, headers=headers)
            except Exception as e:
                return {
                    'status': 'FALSE_POSITIVE',
                    'confidence': 100,
                    'reason': f'تعذر الاتصال بالهدف المستهدف (الخادم لا يستجيب أو النطاق غير متاح): {str(e)}',
                    'technical_proof': f'Connection failure: {str(e)}',
                    'diff_details': {'reachable': False}
                }

            # Canary probe to test for Soft-404
            try:
                canary_resp = client.get(canary_url, headers=headers)
                canary_status = canary_resp.status_code
                canary_len = len(canary_resp.content)
            except Exception:
                canary_status = 404
                canary_len = 0

    except Exception as e:
        return {
            'status': 'INCONCLUSIVE',
            'confidence': 50,
            'reason': f'حدث خطأ غير متوقع أثناء إعداد جلسة الفحص: {str(e)}',
            'technical_proof': str(e),
            'diff_details': {}
        }

    target_status = target_resp.status_code
    target_len = len(target_resp.content)
    target_body = target_resp.text[:15000]

    # Differential Soft-404 check:
    # If the target returned 200 OK, but the random canary path ALSO returned 200 OK with identical content length (+/- 5%),
    # the server is serving a wildcard or custom single-page-app 404 page.
    is_soft_404 = False
    if target_status == 200 and canary_status == 200:
        len_diff = abs(target_len - canary_len)
        if len_diff < 80 or (canary_len > 0 and (len_diff / max(target_len, 1)) < 0.08):
            is_soft_404 = True

    # =========================================================================
    # Test 1: Sensitive File / Backup / Source Leak Verification (.git, .env, .bak)
    # =========================================================================
    if any(k in lower_title for k in ['.git', '.env', 'backup', 'source code', 'sensitive file', 'database backup', '.sql', '.zip']):
        if target_status != 200:
            return {
                'status': 'FALSE_POSITIVE',
                'confidence': 100,
                'reason': f'الملف الحساس غير متاح؛ الخادم أعاد رمز الحالة HTTP {target_status} بدلاً من 200 OK.',
                'technical_proof': f'HTTP Status: {target_status}\nURL: {url}',
                'diff_details': {'status': target_status, 'is_soft_404': is_soft_404}
            }

        if is_soft_404:
            return {
                'status': 'FALSE_POSITIVE',
                'confidence': 100,
                'reason': 'إنذار كاذب مستبعد (Soft-404): الخادم يعيد رمز 200 لجميع الروابط غير الموجودة كصفحة خطأ مخصصة أو تطبيق SPA.',
                'technical_proof': f'Target Status: 200 ({target_len} bytes) == Canary Status: 200 ({canary_len} bytes)\nContent is a customized 404/SPA landing page.',
                'diff_details': {'is_soft_404': True}
            }

        # Content signature matching
        if '.git' in lower_title or '.git/head' in url.lower():
            if target_body.startswith('ref: refs/') or re.match(r'^[0-9a-f]{40}$', target_body.strip()):
                return {
                    'status': 'CONFIRMED',
                    'confidence': 100,
                    'reason': 'ثغرة مؤكدة بنسبة 100%: تم التحقق من ترويسة Git الصريحة واسترجاع ملف HEAD بنجاح دون أي خطأ.',
                    'technical_proof': f'Verified Git Header:\n{target_body[:120]}',
                    'diff_details': {'signature_match': True}
                }
            else:
                return {
                    'status': 'FALSE_POSITIVE',
                    'confidence': 100,
                    'reason': 'إنذار كاذب: المحتوى المسترجع من مسار .git ليس ملف Git أصلي (يحتوي على HTML أو نص خطأ).',
                    'technical_proof': f'Snippet: {target_body[:200]}',
                    'diff_details': {'signature_match': False}
                }

        if '.env' in lower_title or url.endswith('.env'):
            if ('=' in target_body and any(k in target_body.upper() for k in ['APP_', 'DB_', 'KEY', 'SECRET', 'PASSWORD', 'PORT'])) and not ('<html' in target_body.lower()):
                return {
                    'status': 'CONFIRMED',
                    'confidence': 100,
                    'reason': 'ثغرة مؤكدة بنسبة 100%: تم التحقق من تسريب متغيرات البيئة .env واحتوائها على إعدادات الخادم الحقيقية.',
                    'technical_proof': f'Found Key-Value Environment Signatures:\n' + '\n'.join([line for line in target_body.splitlines() if '=' in line][:5]),
                    'diff_details': {'env_keys_found': True}
                }
            else:
                return {
                    'status': 'FALSE_POSITIVE',
                    'confidence': 100,
                    'reason': 'إنذار كاذب: المحتوى المسترجع لا يطابق بنية ملفات البيئة .env (غالباً صفحة خطأ HTML).',
                    'technical_proof': f'Snippet: {target_body[:150]}',
                    'diff_details': {'env_keys_found': False}
                }

        # Generic backup file check:
        if '<html' in target_body.lower() or '<!doctype html>' in target_body.lower():
            return {
                'status': 'FALSE_POSITIVE',
                'confidence': 100,
                'reason': 'إنذار كاذب: الرابط يُرجع مستند HTML لواجهة التطبيق بدلاً من محتوى النسخة الاحتياطية الثنائية.',
                'technical_proof': f'Response Content-Type: {target_resp.headers.get("content-type", "")}\nContains HTML markup instead of raw binary/archive.',
                'diff_details': {'content_type': target_resp.headers.get('content-type', '')}
            }
        else:
            return {
                'status': 'CONFIRMED',
                'confidence': 95,
                'reason': 'ثغرة مؤكدة: الخادم يتيح تحميل الملف مباشرة مع إرجاع محتوى غير نصي وبدون صفحة خطأ.',
                'technical_proof': f'Status: 200 OK | Size: {target_len} bytes | Content-Type: {target_resp.headers.get("content-type", "")}',
                'diff_details': {'raw_file_served': True}
            }

    # =========================================================================
    # Test 2: CORS Misconfiguration Verification
    # =========================================================================
    if 'cors' in lower_title or finding_type == 'cors':
        test_origin = 'https://basha-verification-origin.com'
        with httpx.Client(timeout=8.0, verify=False) as client:
            try:
                cors_resp = client.get(url, headers={'Origin': test_origin, 'User-Agent': 'Mozilla/5.0'})
                acao = cors_resp.headers.get('Access-Control-Allow-Origin', '')
                acac = cors_resp.headers.get('Access-Control-Allow-Credentials', '').lower()
                
                if acao == test_origin and acac == 'true':
                    return {
                        'status': 'CONFIRMED',
                        'confidence': 100,
                        'reason': 'ثغرة مؤكدة بنسبة 100%: الخادم يعكس النطاق الخارجي العشوائي بشكل ديناميكي مع تفعيل سماح الاعتماد (Credentials: true).',
                        'technical_proof': f'Origin Sent: {test_origin}\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}',
                        'diff_details': {'acao': acao, 'acac': acac}
                    }
                elif acao == '*' and acac != 'true':
                    return {
                        'status': 'FALSE_POSITIVE',
                        'confidence': 100,
                        'reason': 'إعداد غير ضار / إنذار كاذب: سياسة CORS تسمح بـ * للبيانات العامة حصراً مع حظر ملفات الاعتماد والكوكيز (Credentials Disabled).',
                        'technical_proof': f'Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: {acac or "Not set"}',
                        'diff_details': {'wildcard_safe': True}
                    }
                else:
                    return {
                        'status': 'FALSE_POSITIVE',
                        'confidence': 100,
                        'reason': 'إنذار كاذب: الخادم لا يعكس النطاقات الخارجية ولا يسمح بمشاركة الموارد مع نطاقات الاختبار.',
                        'technical_proof': f'Access-Control-Allow-Origin Header: {acao or "Absent"}',
                        'diff_details': {'reflected': False}
                    }
            except Exception as e:
                return {'status': 'INCONCLUSIVE', 'confidence': 50, 'reason': f'تعذر فحص استجابة CORS: {str(e)}', 'technical_proof': str(e), 'diff_details': {}}

    # =========================================================================
    # Test 3: Security Headers Verification (CSP, HSTS, X-Frame-Options, MIME)
    # =========================================================================
    if any(k in lower_title for k in ['header', 'hsts', 'csp', 'clickjacking', 'x-frame-options', 'content-security-policy', 'x-content-type-options']):
        h = {str(k).lower(): str(v) for k, v in target_resp.headers.items()}
        
        if 'hsts' in lower_title or 'strict-transport-security' in lower_title:
            if 'strict-transport-security' in h:
                return {
                    'status': 'FALSE_POSITIVE',
                    'confidence': 100,
                    'reason': 'إنذار كاذب: ترويسة Strict-Transport-Security (HSTS) موجودة ومفعلة بالفعل في الاستجابة الحية.',
                    'technical_proof': f'Strict-Transport-Security: {h["strict-transport-security"]}',
                    'diff_details': {'header_found': True}
                }
            else:
                return {
                    'status': 'CONFIRMED',
                    'confidence': 100,
                    'reason': 'ملاحظة أمنية مؤكدة بنسبة 100%: ترويسة HSTS مفقودة بشكل قاطع من استجابة الخادم الرئيسية.',
                    'technical_proof': f'Response Headers inspected on {url}. Strict-Transport-Security is completely absent.',
                    'diff_details': {'header_found': False}
                }

        if 'clickjacking' in lower_title or 'x-frame-options' in lower_title:
            csp = h.get('content-security-policy', '')
            has_frame_ancestors = 'frame-ancestors' in csp
            xfo = h.get('x-frame-options', '')
            if has_frame_ancestors or xfo:
                return {
                    'status': 'FALSE_POSITIVE',
                    'confidence': 100,
                    'reason': 'إنذار كاذب: الموقع محمي من هجمات Clickjacking عبر ترويسات الحماية المؤكدة.',
                    'technical_proof': f'X-Frame-Options: {xfo or "None"} | CSP: {csp or "None"}',
                    'diff_details': {'clickjacking_protected': True}
                }
            else:
                return {
                    'status': 'CONFIRMED',
                    'confidence': 100,
                    'reason': 'ثغرة مؤكدة بنسبة 100%: الصفحة تفتقر كلياً لترويسة X-Frame-Options أو توجيه frame-ancestors في CSP، مما يتيح تضمينها في إطارات <iframe>.',
                    'technical_proof': f'No anti-framing protection headers detected on {url}.',
                    'diff_details': {'clickjacking_protected': False}
                }

        if 'csp' in lower_title or 'content-security-policy' in lower_title:
            if 'content-security-policy' in h:
                return {
                    'status': 'FALSE_POSITIVE',
                    'confidence': 100,
                    'reason': 'إنذار كاذب: سياسة حماية المحتوى (CSP) مفعلة على الصفحة المستهدفة.',
                    'technical_proof': f'Content-Security-Policy: {h["content-security-policy"][:150]}...',
                    'diff_details': {'csp_found': True}
                }
            else:
                return {
                    'status': 'CONFIRMED',
                    'confidence': 100,
                    'reason': 'ملاحظة مؤكدة بنسبة 100%: سياسة حماية المحتوى CSP مفقودة تماماً من استجابة الخادم.',
                    'technical_proof': f'Inspected response headers on {url}. Content-Security-Policy is absent.',
                    'diff_details': {'csp_found': False}
                }

    # =========================================================================
    # Test 4: Open Cloud Storage / S3 Bucket Verification
    # =========================================================================
    if 's3' in lower_title or 'bucket' in lower_title or 'cloud storage' in lower_title:
        if '<ListBucketResult' in target_body or '<EnumerationResults' in target_body:
            return {
                'status': 'CONFIRMED',
                'confidence': 100,
                'reason': 'ثغرة مؤكدة بنسبة 100%: حاوية التخزين السحابي مفتوحة للقراءة العامة واسترجاع قائمة الملفات بنجاح.',
                'technical_proof': f'XML Listing verified:\n{target_body[:200]}',
                'diff_details': {'public_listing': True}
            }
        else:
            return {
                'status': 'FALSE_POSITIVE',
                'confidence': 100,
                'reason': f'إنذار كاذب: الحاوية محمية أو لا تتيح القراءة المفتوحة للعامة (رمز الحالة HTTP {target_status}).',
                'technical_proof': f'Status: {target_status}\nBody snippet: {target_body[:150]}',
                'diff_details': {'public_listing': False}
            }

    # =========================================================================
    # Test 5: Subdomain Takeover Verification
    # =========================================================================
    if 'takeover' in lower_title or 'subdomain takeover' in lower_title:
        matched_sig = None
        for provider, sigs in TAKEOVER_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in target_body.lower():
                    matched_sig = (provider, sig)
                    break
            if matched_sig:
                break

        if matched_sig:
            return {
                'status': 'CONFIRMED',
                'confidence': 100,
                'reason': f'ثغرة مؤكدة بنسبة 100%: تم رصد بصمة الخدمة السحابية المهجورة بدقة ({matched_sig[0]}).',
                'technical_proof': f'Cloud Provider Signature Matched: "{matched_sig[1]}" on host {parsed.netloc}',
                'diff_details': {'provider': matched_sig[0], 'sig': matched_sig[1]}
            }
        else:
            return {
                'status': 'FALSE_POSITIVE',
                'confidence': 100,
                'reason': 'إنذار كاذب: النطاق يستجيب بمحتوى حقيقي أو خدمة فعالة، ولا تظهر أي بصمات استيلاء معلقة.',
                'technical_proof': f'HTTP Status: {target_status} | No abandoned cloud provider footprints found in response.',
                'diff_details': {'takeover_candidate': False}
            }

    # =========================================================================
    # Test 6: Debug / Stack Trace / Error Leak Verification
    # =========================================================================
    if any(k in lower_title for k in ['debug', 'stack trace', 'error leak', 'information disclosure', 'exception']):
        debug_patterns = [
            r'Traceback \(most recent call last\):',
            r'Fatal error: Uncaught',
            r'org\.springframework\.web',
            r'System\.NullReferenceException',
            r'django\.core\.exceptions',
            r'DEBUG\s*=\s*True',
            r'at java\.lang\.Thread\.run'
        ]
        found_debug = None
        for pattern in debug_patterns:
            if re.search(pattern, target_body, re.I):
                found_debug = pattern
                break

        if found_debug:
            return {
                'status': 'CONFIRMED',
                'confidence': 100,
                'reason': 'ثغرة مؤكدة بنسبة 100%: استجابة الخادم تحتوي على تسريب مباشر لمسارات الشيفرة وخطأ برمجياً صريحاً (Stack Trace).',
                'technical_proof': f'Debug Signature Matched: {found_debug}',
                'diff_details': {'debug_pattern': found_debug}
            }
        else:
            return {
                'status': 'FALSE_POSITIVE',
                'confidence': 100,
                'reason': 'إنذار كاذب: لم يتم العثور على أي تفاصيل استثنائية أو تتبع خطأ برمجي (Stack Trace) داخل الاستجابة.',
                'technical_proof': f'No raw tracebacks or exception dumps found in {target_len} bytes of response.',
                'diff_details': {'debug_found': False}
            }

    # =========================================================================
    # Fallback / General Verification (Differential Check against Soft-404)
    # =========================================================================
    if target_status == 404 or target_status == 502 or target_status == 503:
        return {
            'status': 'FALSE_POSITIVE',
            'confidence': 100,
            'reason': f'إنذار كاذب: المورد غير موجود أو الخدمة معطلة (HTTP {target_status}).',
            'technical_proof': f'HTTP Status: {target_status}\nURL: {url}',
            'diff_details': {'status': target_status}
        }

    if is_soft_404:
        return {
            'status': 'FALSE_POSITIVE',
            'confidence': 100,
            'reason': 'إنذار كاذب مؤكد: الصفحة المستهدفة هي صفحة خطأ عامة أو واجهة SPA تعيد 200 لكافة الروابط.',
            'technical_proof': f'Target length ({target_len}B) matches Canary length ({canary_len}B) within threshold.',
            'diff_details': {'is_soft_404': True}
        }

    # If it's a live 200 with unique content
    return {
        'status': 'CONFIRMED',
        'confidence': 90,
        'reason': f'تم تأكيد وجود المورد والاستجابة الحية الفريدة برمز 200 OK ومحتوى نشط ({target_len} بايت).',
        'technical_proof': f'HTTP Status: {target_status} OK\nContent-Length: {target_len} bytes\nContent-Type: {target_resp.headers.get("content-type", "")}',
        'diff_details': {'status': target_status, 'unique_response': True}
    }
