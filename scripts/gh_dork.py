#!/usr/bin/env python3
import requests, json, time, re, os, sys
from datetime import datetime

TOKEN = os.environ.get('GH_TOKEN', '')
if not TOKEN:
    print('ERROR: GH_TOKEN not set', flush=True)
    sys.exit(1)
print(f'Token loaded: {TOKEN[:8]}...', flush=True)
HEADERS = {
    'Authorization': f'token {TOKEN}',
    'Accept': 'application/vnd.github.v3+json',
}

KEY_RE = re.compile(
    r'(AKIA[0-9A-Z]{16}'
    r'|sk_live_[a-zA-Z0-9]{20,}'
    r'|rk_live_[a-zA-Z0-9]{20,}'
    r'|sk-[a-zA-Z0-9]{32,}'
    r'|ghp_[a-zA-Z0-9]{36}'
    r'|gho_[a-zA-Z0-9]{36}'
    r'|xox[baprs]-[0-9A-Za-z\-]{10,}'
    r'|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'
    r'|AIza[0-9A-Za-z\-_]{35}'
    r'|[0-9]{9,10}:[A-Za-z0-9_\-]{35}'
    r'|(?:0x[0-9a-fA-F]{64})'
    r'|(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*[=:]\s*[A-Za-z0-9/+]{20,}'
    r'|(?:binance|bnb|bybit|okx|kraken|coinbase).{0,30}(?:secret|api.?secret)\s*[=:"\s]+([A-Za-z0-9]{32,})'
    r'|(?:private.?key|eth.?key|mnemonic|seed.?phrase)\s*[=:"\s]+([0-9a-fA-F]{64}))',
    re.IGNORECASE
)

DORKS = [
    'AKIA language:python',
    'AKIA language:javascript',
    'AKIA language:php',
    'sk_live_ language:python',
    'sk_live_ language:javascript',
    '"BEGIN RSA PRIVATE KEY" language:python',
    '"BEGIN OPENSSH PRIVATE KEY"',
    'ghp_ language:python',
    'ghp_ language:javascript',
    'xoxb- language:python',
    'xoxb- language:javascript',
    '"aws_secret_access_key" language:python',
    '"aws_secret_access_key" language:javascript',
    'AIzaSy language:python',
    'AIzaSy language:javascript',
]

def search(query, page=1):
    url = 'https://api.github.com/search/code'
    params = {'q': query, 'per_page': 30, 'page': page}
    r = requests.get(url, headers=HEADERS, params=params, timeout=15)
    if r.status_code == 403:
        reset = int(r.headers.get('X-RateLimit-Reset', time.time() + 60))
        wait = max(reset - time.time(), 5)
        print(f'  rate limit — sleeping {wait:.0f}s', flush=True)
        time.sleep(wait)
        return None
    if r.status_code != 200:
        print(f'  error {r.status_code}: {r.text[:100]}', flush=True)
        return None
    return r.json()

def get_raw(url):
    raw = url.replace('github.com', 'raw.githubusercontent.com')
    raw = raw.replace('/blob/', '/')
    r = requests.get(raw, headers=HEADERS, timeout=10)
    if r.status_code == 200:
        return r.text[:8000]
    return ''

findings = []

for dork in DORKS:
    print(f'\nDORK: {dork}', flush=True)
    result = search(dork)
    if not result:
        continue
    items = result.get('items', [])
    total = result.get('total_count', 0)
    print(f'  {total} results, checking {len(items)}', flush=True)

    for item in items:
        html_url = item.get('html_url', '')
        repo = item.get('repository', {}).get('full_name', '')
        path = item.get('path', '')

        try:
            content = get_raw(html_url)
            time.sleep(0.3)
        except:
            continue

        if not content:
            print(f'  empty content: {repo}/{path}', flush=True)
            continue

        secrets = list(set(m.group(0)[:150] for m in KEY_RE.finditer(content)))
        if secrets:
            entry = {
                'url': html_url,
                'repo': repo,
                'path': path,
                'secrets': secrets[:10],
                'found_at': datetime.utcnow().isoformat()
            }
            findings.append(entry)
            print(f'  HIT: {repo}/{path} — {len(secrets)} secrets', flush=True)
            for s in secrets[:3]:
                print(f'    -> {s[:100]}', flush=True)
        else:
            print(f'  no match: {repo}/{path}', flush=True)

    time.sleep(2)

print(f'\nTotal hits: {len(findings)}', flush=True)

with open('gh_findings.jsonl', 'w') as f:
    for r in findings:
        f.write(json.dumps(r) + '\n')

print('Written to gh_findings.jsonl')
