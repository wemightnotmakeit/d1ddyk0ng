#!/usr/bin/env python3
import json, base64

KEY = b'mw9x2k4p7n1q8r5t'

def xor_encrypt(s):
    b = s.encode()
    return base64.b64encode(bytes(b[i] ^ KEY[i % len(KEY)] for i in range(len(b)))).decode()

out = []
for line in open('gh_findings.jsonl'):
    line = line.strip()
    if not line:
        continue
    r = json.loads(line)
    r['secrets'] = [xor_encrypt(s) for s in r.get('secrets', [])]
    out.append(json.dumps(r))

with open('data/gh_cumulative.jsonl', 'a') as f:
    for line in out:
        f.write(line + '\n')

print(f'Encoded and saved {len(out)} findings')
