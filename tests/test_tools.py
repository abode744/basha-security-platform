import json
from app.tools import TOOL_DEFS, available, tool_modes, resolve_tool_name, TOOL_ALIASES

def test_tool_definitions_and_json():
    with open('tools/tools.json', 'r', encoding='utf-8') as f:
        data = json.load(f)
    assert len(TOOL_DEFS) >= 100, f"Expected at least 100 tools, got {len(TOOL_DEFS)}"
    assert len(data) == len(TOOL_DEFS), f"tools.json ({len(data)}) != TOOL_DEFS ({len(TOOL_DEFS)})"
    for k, v in TOOL_DEFS.items():
        assert k in data, f"Tool {k} missing from tools.json"
        assert 'stage' in v, f"Stage missing from {k}"
        assert 'profiles' in v, f"Profiles missing from {k}"
        assert 'desc' in v, f"Description missing from {k}"

def test_tool_availability_and_modes():
    avail = available()
    modes = tool_modes()
    assert len(avail) == len(TOOL_DEFS)
    assert len(modes) == len(TOOL_DEFS)
    for k in TOOL_DEFS:
        assert avail[k] is True
        assert modes[k] in ('BINARY', 'ENGINE')

def test_tool_aliases_and_categories():
    assert len(TOOL_ALIASES) >= 20
    test_cases = {
        'shodan': 'shodan_osint',
        'can-i-take-over-xyz': 'canitakeoverxyz',
        'git-dumper': 'gitdumper',
        'testssl.sh': 'testssl',
        'crt.sh': 'crtsh',
        'owasp-zap': 'zap',
        'js-scan': 'js_scan',
        'dependency-check': 'dependency_check',
        'qualys': 'qualys_was',
        'greenbone': 'openvas',
        'jwt-tool': 'jwt_tool',
        'saml-raider': 'saml_raider',
        'oauth-scan': 'oauthscan',
        'dompurify-tester': 'dompurify_tester',
        'aem-hacker': 'aem_hacker',
    }
    for alias, expected in test_cases.items():
        resolved = resolve_tool_name(alias)
        assert resolved == expected, f"Alias {alias} resolved to {resolved}, expected {expected}"
        assert resolved in TOOL_DEFS, f"Resolved key {resolved} not in TOOL_DEFS"

if __name__ == '__main__':
    test_tool_definitions_and_json()
    test_tool_availability_and_modes()
    test_tool_aliases_and_categories()
    print("All tool matrix and alias tests passed successfully!")

