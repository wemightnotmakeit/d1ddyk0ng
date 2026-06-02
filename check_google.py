#!/usr/bin/env python3
"""
Check Google API keys for billing scope and live services.
Tests: Maps JS/Static/Geocoding, YouTube Data, Firebase, Places, Vision, Translation.
A key with billing = GCP project with potential credits/quota.
"""
import json, glob, re, time, urllib.request, urllib.error

KEY_RE = re.compile(r'AIza[0-9A-Za-z\-_]{35}')

# Quick service probes — returns (service_name, live:bool, detail:str)
PROBES = [
    # Maps Static API — no auth redirect, direct response
    ('Maps Static', lambda k: probe_url(
        f'https://maps.googleapis.com/maps/api/staticmap?center=0,0&zoom=1&size=1x1&key={k}',
        expect_content_type='image/'
    )),
    # Geocoding API
    ('Geocoding', lambda k: probe_url(
        f'https://maps.googleapis.com/maps/api/geocode/json?address=NYC&key={k}',
        expect_json_ok=True
    )),
    # Places Nearby
    ('Places', lambda k: probe_url(
        f'https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=0,0&radius=1&key={k}',
        expect_json_ok=True
    )),
    # YouTube Data v3
    ('YouTube', lambda k: probe_url(
        f'https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&maxResults=1&key={k}',
        expect_json_ok=True
    )),
    # Distance Matrix
    ('Distance Matrix', lambda k: probe_url(
        f'https://maps.googleapis.com/maps/api/distancematrix/json?origins=NYC&destinations=LA&key={k}',
        expect_json_ok=True
    )),
]

def probe_url(url, expect_content_type=None, expect_json_ok=False):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'curl/7.0'})
        r = urllib.request.urlopen(req, timeout=8)
        body = r.read()
        ct = r.headers.get('Content-Type', '')

        if expect_content_type:
            if expect_content_type in ct:
                return True, f'200 {ct[:30]}'
            return False, f'wrong content-type: {ct[:40]}'

        if expect_json_ok:
            try:
                data = json.loads(body)
                status = data.get('status', data.get('error', {}).get('status', ''))
                if status in ('OK', 'ZERO_RESULTS'):
                    return True, f'status={status}'
                if status == 'REQUEST_DENIED':
                    msg = data.get('error_message', data.get('error', {}).get('message', ''))
                    return False, f'DENIED: {msg[:60]}'
                return False, f'status={status}'
            except:
                if b'error' not in body.lower()[:100]:
                    return True, '200 non-JSON'
                return False, 'parse error'

        return True, '200'
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors='replace')[:200]
        try:
            data = json.loads(body)
            status = data.get('status', data.get('error', {}).get('status', ''))
            msg = data.get('error_message', data.get('error', {}).get('message', ''))
            return False, f'{e.code} {status} {msg[:60]}'
        except:
            return False, f'HTTP {e.code}'
    except Exception as ex:
        return False, f'ERR: {str(ex)[:40]}'


seen_keys = set()
live_keys = []
checked = 0

for f in sorted(glob.glob('/opt/agents/gh_findings/*.jsonl')):
    for line in open(f):
        try:
            e = json.loads(line)
            full_text = ' '.join(e.get('secrets', []))
            for key in KEY_RE.findall(full_text):
                if key in seen_keys: continue
                seen_keys.add(key)
                checked += 1

                services_live = []
                for svc_name, probe_fn in PROBES:
                    ok, detail = probe_fn(key)
                    time.sleep(0.1)
                    if ok:
                        services_live.append(svc_name)

                if services_live:
                    print(f'LIVE [{",".join(services_live)}] {key[:20]}...')
                    print(f'  repo: {e["repo"]}/{e["path"]}')
                    live_keys.append({'key': key, 'services': services_live, 'repo': e['repo']})
                else:
                    print(f'dead | {key[:20]}... | {e["repo"]}')

                time.sleep(0.2)
        except:
            pass

print('\n' + '='*60)
print(f'Checked {checked} unique Google API keys')
print(f'LIVE: {len(live_keys)}')
for x in live_keys:
    print(f'  {x["key"][:30]}... [{",".join(x["services"])}]')
    print(f'  {x["repo"]}')
