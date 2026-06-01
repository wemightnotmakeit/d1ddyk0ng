#!/usr/bin/env python3
import json, base64

out = []
for line in open('gh_findings.jsonl'):
    line = line.strip()
    if not line:
        continue
    r = json.loads(line)
    r['secrets'] = [base64.b64encode(s.encode()).decode() for s in r.get('secrets', [])]
    out.append(json.dumps(r))

with open('data/gh_cumulative.jsonl', 'a') as f:
    for line in out:
        f.write(line + '\n')

print(f'Encoded and saved {len(out)} findings')
