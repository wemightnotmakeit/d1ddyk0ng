#!/usr/bin/env python3
"""
Picks the next BATCH_SIZE unscanned ranges from ranges_queue.txt.
Outputs JSON for GitHub Actions dynamic matrix.
Cycles through VPS/hosting ranges where exposed services actually live.
"""
import json, sys, os

BATCH_SIZE = 250
QUEUE_FILE  = 'data/ranges_queue.txt'
DONE_FILE   = 'data/ranges_done.txt'
BATCH_FILE  = 'data/current_batch.txt'

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

# Pick next batch (exclude already done)
available = sorted(queue - done)
batch = available[:BATCH_SIZE]

if not batch:
    # All done — reset and cycle again
    print('All ranges scanned — resetting done list', file=sys.stderr)
    done = set()
    save_file(DONE_FILE, done)
    available = sorted(queue)
    batch = available[:BATCH_SIZE]

# Save batch for collect job to mark as done
with open(BATCH_FILE, 'w') as f:
    for r in batch:
        f.write(r + '\n')

# Output matrix JSON
matrix = {'block': batch}
print(json.dumps(matrix))
