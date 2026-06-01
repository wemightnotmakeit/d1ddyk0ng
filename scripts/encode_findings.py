#!/usr/bin/env python3
import json, base64, os, glob

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

os.makedirs('data', exist_ok=True)
existing = glob.glob('data/findings_*.jsonl')
nums = [int(f.split('_')[1].split('.')[0]) for f in existing if f.split('_')[1].split('.')[0].isdigit()]
next_num = max(nums) + 1 if nums else 1

out_file = f'data/findings_{next_num}.jsonl'
with open(out_file, 'w') as f:
    for line in out:
        f.write(line + '\n')

print(f'Encoded and saved {len(out)} findings to {out_file}')
