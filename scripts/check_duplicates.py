import json
import re
from app.tools import TOOL_DEFS

# 1. Check raw text of tools.py for duplicate dictionary keys
with open('app/tools.py', 'r', encoding='utf-8') as f:
    tools_py_raw = f.read()

# Match all keys: 'something': {
py_keys = re.findall(r"'([a-zA-Z0-9_\-]+)'\s*:\s*\{", tools_py_raw)
print(f"Total regex-matched keys in app/tools.py: {len(py_keys)}")
print(f"Unique keys in app/tools.py dict: {len(TOOL_DEFS)}")

py_key_counts = {}
for k in py_keys:
    py_key_counts[k] = py_key_counts.get(k, 0) + 1

py_dups = {k: v for k, v in py_key_counts.items() if v > 1}
if py_dups:
    print(f"[!] DUPLICATE KEYS IN app/tools.py: {py_dups}")
else:
    print("[V] ZERO duplicate keys in app/tools.py!")

# 2. Check raw text of tools/tools.json for duplicate keys
with open('tools/tools.json', 'r', encoding='utf-8') as f:
    tools_json_raw = f.read()

json_keys = re.findall(r'"([a-zA-Z0-9_\-]+)"\s*:\s*\{', tools_json_raw)
print(f"Total regex-matched keys in tools/tools.json: {len(json_keys)}")

with open('tools/tools.json', 'r', encoding='utf-8') as f:
    tj = json.load(f)
print(f"Unique keys in tools.json: {len(tj)}")

json_key_counts = {}
for k in json_keys:
    json_key_counts[k] = json_key_counts.get(k, 0) + 1

json_dups = {k: v for k, v in json_key_counts.items() if v > 1}
if json_dups:
    print(f"[!] DUPLICATE KEYS IN tools/tools.json: {json_dups}")
else:
    print("[V] ZERO duplicate keys in tools/tools.json!")

# 3. Check symmetric parity between tools.py and tools.json
in_py_not_json = set(TOOL_DEFS.keys()) - set(tj.keys())
in_json_not_py = set(tj.keys()) - set(TOOL_DEFS.keys())

print(f"Keys in tools.py not in tools.json: {in_py_not_json}")
print(f"Keys in tools.json not in tools.py: {in_json_not_py}")

assert len(py_dups) == 0, "Duplicate keys found in app/tools.py"
assert len(json_dups) == 0, "Duplicate keys found in tools/tools.json"
assert in_py_not_json == set(), "tools.py has keys missing from tools.json"
assert in_json_not_py == set(), "tools.json has keys missing from tools.py"
print("\n[SUCCESS] 100% Unique, Zero Duplicates, Perfect Parity across all 119 tools!")
