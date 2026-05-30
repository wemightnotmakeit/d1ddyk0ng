#!/usr/bin/env python3
"""
Picks the next BATCH_SIZE unscanned ranges from ranges_queue.txt.
Outputs JSON for GitHub Actions dynamic matrix.
Also fetches fresh AWS/GCP/Azure ranges to keep the queue topped up.
"""
import json, sys, os, requests

BATCH_SIZE = 250
QUEUE_FILE  = 'data/ranges_queue.txt'
DONE_FILE   = 'data/ranges_done.txt'
BATCH_FILE  = 'data/current_batch.txt'

HONEYPOT_CIDRS = {
    # Known honeypot ranges - skip entirely
    '0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8',
    '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16',
}

def fetch_aws_ranges():
    try:
        r = requests.get('https://ip-ranges.amazonaws.com/ip-ranges.json', timeout=15)
        data = r.json()
        ranges = set()
        for p in data.get('prefixes', []):
            cidr = p.get('ip_prefix', '')
            # Only /16 blocks, skip /8 /10 /13 etc
            if cidr.endswith('/16') and not any(cidr.startswith(h.split('/')[0][:3]) for h in HONEYPOT_CIDRS):
                ranges.add(cidr)
        return ranges
    except:
        return set()

def fetch_gcp_ranges():
    try:
        r = requests.get('https://www.gstatic.com/ipranges/cloud.json', timeout=15)
        data = r.json()
        ranges = set()
        for p in data.get('prefixes', []):
            cidr = p.get('ipv4Prefix', '')
            if cidr.endswith('/16'):
                ranges.add(cidr)
        return ranges
    except:
        return set()

def load_file(path):
    try:
        with open(path) as f:
            return set(line.strip() for line in f if line.strip() and not line.startswith('#'))
    except:
        return set()

def save_file(path, items):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        for item in sorted(items):
            f.write(item + '\n')

os.makedirs('data', exist_ok=True)

# Load current state
queue = load_file(QUEUE_FILE)
done  = load_file(DONE_FILE)

# Refill queue from live cloud provider ranges when running low
if len(queue) < BATCH_SIZE * 2:
    print('Queue low — fetching fresh cloud ranges...', file=sys.stderr)
    fresh = fetch_aws_ranges() | fetch_gcp_ranges()
    new_ranges = fresh - done - queue
    print(f'Adding {len(new_ranges)} new ranges to queue', file=sys.stderr)
    queue |= new_ranges
    save_file(QUEUE_FILE, queue)

# Pick next batch (exclude already done)
available = sorted(queue - done)
batch = available[:BATCH_SIZE]

if not batch:
    # All done — reset and start over with fresh fetch
    print('All ranges scanned — resetting done list', file=sys.stderr)
    done = set()
    save_file(DONE_FILE, done)
    batch = available[:BATCH_SIZE]

# Save batch for collect job to mark as done
with open(BATCH_FILE, 'w') as f:
    for r in batch:
        f.write(r + '\n')

# Output matrix JSON
matrix = {'block': batch}
print(json.dumps(matrix))
