import json
from app.tools import TOOL_DEFS, available, tool_modes

def test_tool_definitions_and_json():
    with open('tools/tools.json', 'r', encoding='utf-8') as f:
        data = json.load(f)
    assert len(TOOL_DEFS) >= 60, f"Expected at least 60 tools, got {len(TOOL_DEFS)}"
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

if __name__ == '__main__':
    test_tool_definitions_and_json()
    test_tool_availability_and_modes()
    print("All tool matrix tests passed successfully!")
