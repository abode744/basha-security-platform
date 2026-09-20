from app.tools import TOOL_DEFS
with open('app/local_worker.py', 'r', encoding='utf-8') as f:
    worker_code = f.read()

unreferenced = []
for tool_name in TOOL_DEFS:
    if f"'{tool_name}'" not in worker_code and f'"{tool_name}"' not in worker_code:
        unreferenced.append(tool_name)

print(f"Total tools in TOOL_DEFS: {len(TOOL_DEFS)}")
print(f"Unreferenced in local_worker.py: {len(unreferenced)}")
for u in unreferenced:
    print(" ", u)
