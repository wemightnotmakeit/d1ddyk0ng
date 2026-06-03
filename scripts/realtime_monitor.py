#!/usr/bin/env python3
"""Real-time GitHub event monitor — checks NEW commits as they happen."""
import requests, json, time, re, os, sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

TOKEN = os.environ.get('GH_TOKEN', '')
HEADERS = {
    'Authorization': f'token {TOKEN}',
    'Accept': 'application/vnd.github.v3+json',
}

KEY_RE = re.compile(
    r'(sk_live_[a-zA-Z0-9]{24,}'
    r'|AKIA[0-9A-Z]{16}'
    r'|(?:BINANCE_SECRET|BINANCE_API_SECRET|BYBIT_API_SECRET|OKX_SECRET|KUCOIN_API_SECRET|MEXC_SECRET)[^=\n]*=\s*([A-Za-z0-9]{36,})'
    r'|(?:SOLANA_PRIVATE_KEY|SOL_PRIVATE_KEY|ANCHOR_WALLET|DEPLOYER_PRIVATE_KEY|PUMP_WALLET|SNIPER_WALLET|BOT_WALLET'
    r'|PHANTOM_PRIVATE_KEY|PHANTOM_WALLET|PHANTOM_KEY|MY_WALLET|MAIN_WALLET|HOT_WALLET|TRADER_WALLET'
    r'|BUYER_WALLET|TRADE_WALLET|FUNDING_WALLET|SIGNER_WALLET|FEE_WALLET|VOLUME_WALLET|JITO_WALLET'
    r'|BUNDLER_WALLET|COPY_WALLET|WALLET_KEY|WALLET_PRIVATE_KEY|FEE_PAYER_KEY)\s*[=:"\'\\s]+([1-9A-HJ-NP-Za-km-z]{87,88})'
    r'|"secretKey"\s*:\s*\[(\d{1,3}(?:,\s*\d{1,3}){63})\]'
    r'|bs58\.decode\s*\(\s*["\']([1-9A-HJ-NP-Za-km-z]{87,88})'
    r'|(?:PRIVATE_KEY|ETH_PRIVATE_KEY|DEPLOYER_KEY|MEV_BOT_KEY)\s*[=:"\'\\s]+(0x[a-fA-F0-9]{64})'
    r'|(?:MNEMONIC|SEED_PHRASE|SECRET_RECOVERY_PHRASE)\s*[=:"]+\s*([a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z][a-z ]*)'
    r'|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)',
    re.IGNORECASE
)

seen_commits = set()
last_etag = None

def get_events():
    global last_etag
    hdrs = dict(HEADERS)
    if last_etag:
        hdrs['If-None-Match'] = last_etag
    r = requests.get('https://api.github.com/events?per_page=100', headers=hdrs, timeout=15)
    if r.status_code == 304:
        return []
    if r.status_code != 200:
        return []
    last_etag = r.headers.get('ETag', '')
    return r.json()

def get_commit_diff(repo, sha):
    url = f'https://api.github.com/repos/{repo}/commits/{sha}'
    r = requests.get(url, headers=HEADERS, timeout=10)
    if r.status_code != 200:
        return ''
    data = r.json()
    patches = [f.get('patch', '') for f in data.get('files', []) if f.get('patch')]
    return '\n'.join(patches)[:20000]

findings = []
print(f'[{datetime.now():%H:%M:%S}] Monitor started. Token: {"set" if TOKEN else "MISSING"}', flush=True)

poll_count = 0
while True:
    try:
        events = get_events()
        poll_count += 1
        push_events = [e for e in events if e.get('type') == 'PushEvent']
        new_commits = []
        for event in push_events:
            repo = event.get('repo', {}).get('name', '')
            for commit in event.get('payload', {}).get('commits', []):
                sha = commit.get('sha', '')
                if sha and sha not in seen_commits:
                    seen_commits.add(sha)
                    new_commits.append((repo, sha, commit.get('message', '')[:80]))

        if new_commits:
            print(f'[{datetime.now():%H:%M:%S}] Poll #{poll_count}: {len(new_commits)} new commits', flush=True)
            def check_commit(args):
                repo, sha, msg = args
                diff = get_commit_diff(repo, sha)
                if not diff:
                    return None
                secrets = list(set(m.group(0)[:200] for m in KEY_RE.finditer(diff)))
                if secrets:
                    return {'repo': repo, 'sha': sha, 'msg': msg, 'secrets': secrets[:5],
                            'url': f'https://github.com/{repo}/commit/{sha}',
                            'found_at': datetime.utcnow().isoformat()}
                return None
            with ThreadPoolExecutor(max_workers=8) as ex:
                results = list(ex.map(check_commit, new_commits))
            for r in results:
                if r:
                    findings.append(r)
                    print(f'*** HIT: {r["repo"]} | {r["msg"][:60]}', flush=True)
                    for s in r['secrets']:
                        print(f'    {s[:120]}', flush=True)
                    with open('/opt/agents/realtime_hits.jsonl', 'a') as f:
                        f.write(json.dumps(r) + '\n')
        elif poll_count % 10 == 0:
            print(f'[{datetime.now():%H:%M:%S}] Poll #{poll_count}: waiting...', flush=True)

        time.sleep(30)
    except KeyboardInterrupt:
        break
    except Exception as e:
        print(f'err: {e}', flush=True)
        time.sleep(10)

print(f'Total hits: {len(findings)}')
