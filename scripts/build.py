#!/usr/bin/env python3
import re, sys, urllib.request
from datetime import datetime, timezone

TIERS = ['lite', 'normal', 'full']
DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$')
HOSTS_IPS = {'0.0.0.0', '127.0.0.1', '::', '::1'}


def read_lines(path):
    try:
        with open(path, encoding='utf-8') as f:
            return [l.strip() for l in f]
    except FileNotFoundError:
        return []


def parse_line(line):
    line = line.split('#')[0].strip()
    if not line or line.startswith(('!', '[')):
        return None
    if line.startswith('||') and line.endswith('^'):
        line = line[2:-1]
    parts = line.split()
    if len(parts) >= 2 and parts[0] in HOSTS_IPS:
        line = parts[1]
    elif len(parts) != 1:
        return None
    d = line.lower().rstrip('.')
    return d if DOMAIN_RE.match(d) else None


def fetch(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'filter-builder'})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode('utf-8', errors='ignore').splitlines()


def load_sources():
    out = {t: [] for t in TIERS}
    for l in read_lines('sources.txt'):
        if not l or l.startswith('#'):
            continue
        parts = l.split()
        if len(parts) != 2 or parts[0] not in TIERS:
            print(f'SKIP bad line: {l}', file=sys.stderr)
            continue
        out[parts[0]].append(parts[1])
    return out


def main():
    sources = load_sources()
    own = {t: set() for t in TIERS}
    failed = 0

    for tier in TIERS:
        for url in sources[tier]:
            try:
                before = len(own[tier])
                for line in fetch(url):
                    d = parse_line(line)
                    if d:
                        own[tier].add(d)
                print(f'OK   [{tier}] {url} (+{len(own[tier]) - before})')
            except Exception as e:
                failed += 1
                print(f'FAIL [{tier}] {url}: {e}', file=sys.stderr)

    # ถ้ามี source ไหนพัง ไม่เขียนไฟล์ เพื่อไม่ให้ลิสต์หดโดยไม่ตั้งใจ
    if failed:
        sys.exit(f'{failed} source(s) failed; keeping old blocklists')

    custom = {parse_line(l) for l in read_lines('custom.txt')} - {None}
    whitelist = {parse_line(l) for l in read_lines('whitelist.txt')} - {None}

    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

    cumulative = set()
    for tier in TIERS:
        cumulative |= own[tier]
        final = (cumulative | custom) - whitelist
        if not final:
            sys.exit(f'tier {tier} is empty; aborting')
        with open(f'blocklist-{tier}.txt', 'w', encoding='utf-8') as f:
            f.write(f'# Title: Custom blocklist ({tier})\n')
            f.write(f'# Domains: {len(final)}\n')
            f.write(f'# Updated: {now}\n')
            f.write('# Sources:\n')
            for t in TIERS[:TIERS.index(tier) + 1]:
                for url in sources[t]:
                    f.write(f'#   {url}\n')
            f.write('\n'.join(sorted(final)) + '\n')
        print(f'Total [{tier}]: {len(final)} domains')


if __name__ == '__main__':
    main()