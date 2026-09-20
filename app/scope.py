import ipaddress
import re
from urllib.parse import urlsplit

def norm_host(v):
    if not v:
        raise ValueError('الرجاء إدخال النطاق أو عنوان IP المستهدف')
    v = str(v).strip()
    # Strip URL schemes like https:// or http://
    if '://' in v:
        try:
            parsed = urlsplit(v)
            v = parsed.hostname or parsed.netloc or v
        except Exception:
            v = re.sub(r'^[a-zA-Z]+://', '', v)
    # Strip path, query, hash, credentials
    for delimiter in ['/', '?', '#', '@']:
        if delimiter in v:
            v = v.split(delimiter)[0]
    # Strip port if host:port (handle IPv6 brackets if any)
    if ':' in v and not v.count(':') > 1:
        v = v.split(':')[0]
    v = v.strip().lower().rstrip('.')
    # Localhost alias
    if v == 'localhost':
        return '127.0.0.1'
    # IP address
    try:
        return ipaddress.ip_address(v).compressed
    except ValueError:
        pass
    # Wildcard prefix
    is_wildcard = False
    if v.startswith('*.'):
        is_wildcard = True
        v = v[2:]
    # IDN / Arabic domain conversion
    try:
        v = v.encode('idna').decode('ascii')
    except Exception:
        pass
    if len(v) > 253 or not re.fullmatch(r'[a-z0-9.-]+', v) or '..' in v:
        raise ValueError(f'Invalid hostname/IP: {v}')
    labels = v.split('.')
    if any(not x or x.startswith('-') or x.endswith('-') for x in labels):
        raise ValueError(f'Invalid hostname/IP: {v}')
    return f'*.{v}' if is_wildcard else v

def validate(root, include, exclude):
    r = norm_host(root)
    if r.startswith('*.'):
        r = r[2:]
    inc = [norm_host(x) for x in (include or [r]) if x.strip()]
    exc = [norm_host(x) for x in (exclude or []) if x.strip()]
    if r not in inc and f'*.{r}' not in inc:
        inc.append(r)
    return r, sorted(set(inc)), sorted(set(exc))

def in_scope(host, root, include, exclude):
    try:
        h = norm_host(host)
    except ValueError:
        return False
    if h.startswith('*.'):
        h = h[2:]
    def m(h, p):
        if p.startswith('*.'):
            base = p[2:]
            return h == base or h.endswith('.' + base)
        return h == p or h.endswith('.' + p)
    return any(m(h, p) for p in include) and not any(m(h, p) for p in exclude) and (m(h, root) or any(m(h, p) for p in include))

def validate_url(url, root, include, exclude):
    try:
        u = urlsplit(url)
        return u.scheme in {'http', 'https'} and bool(u.hostname) and not u.username and not u.password and in_scope(u.hostname, root, include, exclude)
    except Exception:
        return False
