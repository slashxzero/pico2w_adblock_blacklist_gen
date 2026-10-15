#!/usr/bin/env python3
"""Preprocess hosts/domain blocklists into the hash list the Pico 2 W ad-blocker
looks domains up in. Hash = 64-bit FNV-1a truncated to 40 bits (same as the firmware
and as esp32-c3-adblock, MIT).

Two steps shrink the list before it is written:
  1. Redundant subdomains are dropped: the firmware also checks every parent of a
     queried name, so "ads.example.com" adds nothing once "example.com" is listed.
  2. Format v2 (default) stores the sorted hashes as Golomb-Rice coded gaps in 2^b
     buckets: ~22 bits per entry instead of 40, so the same 1.9 MB partition holds
     ~700k domains with the same false-positive rate as before.
     --v1 writes the old uncompressed format (5 bytes per hash, max 392,396 entries;
     the format of esp32-c3-adblock and of firmware before v1.2.0).

Format v2 (little-endian):
  header 20 bytes: "PBL2", u8 hash_bits (40), u8 bucket_bits b, u8 rice_k, u8 0,
                   u32 count, u32 stream_bits, u32 CRC-32 (zlib) of everything after the header
  table  (2^b + 1) x u32: bit offset of each bucket in the stream (last = stream_bits)
  stream bit-packed, MSB first. Bucket i holds the hashes whose top b bits are i; each
         is coded as gap = low_bits - previous_low_bits - 1 (previous starts at -1):
         gap >> k ones, a zero, then the k low bits of gap.

Usage: build_blocklist.py [--v1] [--allow-missing] [out.bin] [src ...]
  src = local file or URL. With none given, downloads StevenBlack base + Hagezi Pro
  (~216k entries after step 1, 2026-10): ads, trackers, malware, telemetry; social
  and messaging apps keep working. Bigger combinations that fit (2026-10, after step 1):
    SB + Hagezi Pro++ + TIF mini   ~375k      SB + Hagezi Ultimate + TIF mini   ~400k
  Builds larger than the partition are refused (exit code 1).
"""
import re
import sys, os, math, struct, urllib.request, zlib

HASH_BYTES = 5                          # 40-bit hashes -- must match firmware
MASK = (1 << (HASH_BYTES * 8)) - 1
FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME  = 0x100000001b3
U64 = (1 << 64) - 1

# Space the firmware has for the file: Blocklist partition (1920 KB) minus its 4 KB header
# sector -- keep in sync with src/app_config.h / partitions.json.
DATA_CAP = 1920 * 1024 - 4096
MAGIC_V2 = b'PBL2'

# Default: StevenBlack base + Hagezi Pro (Hagezi's recommended "balanced" tier).
# Other tiers: light, pro.plus, ultimate; threat intel: tif.mini, tif.medium -- swap or add file names.
HAGEZI = 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/'
DEFAULT_SOURCES = [
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',   # base: ads + malware
    HAGEZI + 'pro-onlydomains.txt',                                      # Hagezi Pro (domain + subdomains)
]

# ||domain^  or  @@||domain^  optionally followed by $modifiers
ADG = re.compile(r'^(@@)?\|\|([a-z0-9._-]+)\^?(\$.*)?$', re.I)

ALLOW_MISSING = False

def fnv(b: bytes) -> int:
    h = FNV_OFFSET
    for c in b:
        h = ((h ^ c) * FNV_PRIME) & U64
    return h & MASK                      # truncate to HASH_BYTES

def norm(d: str) -> str:
    d = d.strip().lower().lstrip('*').lstrip('.').rstrip('.')
    return d[4:] if d.startswith('www.') else d

def read_source(src: str) -> str:
    if os.path.exists(src):
        return open(src, errors='ignore').read()
    print(f'  downloading {src} ...', file=sys.stderr)
    return urllib.request.urlopen(src, timeout=180).read().decode('utf-8', 'ignore')

def prune(domains: set) -> set:
    """Drop names whose parent (2+ labels, like the firmware's lookup walk) is listed too."""
    keep = set()
    for d in domains:
        labels = d.split('.')
        if not any('.'.join(labels[i:]) in domains for i in range(1, len(labels) - 1)):
            keep.add(d)
    return keep

class BitWriter:
    def __init__(self):
        self.out, self.acc, self.n, self.pos = bytearray(), 0, 0, 0
    def put(self, value: int, bits: int):          # MSB first
        self.acc = (self.acc << bits) | value
        self.n += bits; self.pos += bits
        while self.n >= 8:
            self.n -= 8
            self.out.append((self.acc >> self.n) & 0xFF)
        self.acc &= (1 << self.n) - 1
    def finish(self) -> bytes:
        if self.n: self.out.append((self.acc << (8 - self.n)) & 0xFF)
        return bytes(self.out)

def encode_v2(hashes: list) -> bytes:
    """hashes: sorted, unique, < 2**40."""
    n, hb = len(hashes), HASH_BYTES * 8
    b = max(0, min(16, math.ceil(math.log2(max(n / 48, 1)))))      # ~24-48 entries per bucket
    low = hb - b
    gaps, buckets, prev, cur = [], [], -1, -1
    for h in hashes:
        bk = h >> low
        if bk != cur: cur, prev = bk, -1
        lo = h & ((1 << low) - 1)
        gaps.append(lo - prev - 1); buckets.append(bk); prev = lo
    k0 = max(0, int(math.log2(max((1 << hb) / n * math.log(2), 1))))
    k = min(range(max(0, k0 - 2), k0 + 3), key=lambda k: sum((g >> k) for g in gaps) + len(gaps) * (k + 1))
    w, table, i = BitWriter(), [], 0
    for bk in range(1 << b):
        table.append(w.pos)
        while i < n and buckets[i] == bk:
            g = gaps[i]; q = g >> k
            w.put(((1 << q) - 1) << 1, q + 1)                     # q ones, then a zero
            if k: w.put(g & ((1 << k) - 1), k)
            i += 1
    table.append(w.pos)
    stream = w.finish()
    body = struct.pack(f'<{len(table)}I', *table) + stream
    return struct.pack('<4sBBBBIII', MAGIC_V2, hb, b, k, 0, n, w.pos, zlib.crc32(body)) + body

def main():
    global ALLOW_MISSING
    flags = {'--allow-missing', '--v1'}
    args = [a for a in sys.argv[1:] if a not in flags]
    ALLOW_MISSING = '--allow-missing' in sys.argv[1:]
    v1 = '--v1' in sys.argv[1:]
    out = args[0] if args else 'blocklist.bin'
    sources = args[1:] if len(args) > 1 else DEFAULT_SOURCES

    domains, allow = set(), set()
    skipped = 0
    for src in sources:
        try:
            data = read_source(src)
        except Exception as e:
            # Fail loudly: silently dropping a source shrinks the list without anyone noticing
            # (happened when Hagezi retired domains/light.txt). Pass --allow-missing to continue.
            print(f'  !! FAILED to read {src}: {e}', file=sys.stderr)
            if not ALLOW_MISSING: sys.exit(1)
            continue
        for line in data.splitlines():
            line = line.split('#', 1)[0].strip() if not line.lstrip().startswith(('||', '@@')) else line.strip()
            if not line or line[0] in '!/[':
                continue
            # AdGuard / ABP basic rules: ||example.com^  and allow rules @@||example.com^
            m = ADG.match(line)
            if m:
                if m.group(3):            # has $modifiers (client/dnstype/etc.) -> can't express, skip
                    skipped += 1; continue
                (allow if m.group(1) else domains).add(norm(m.group(2)))
                continue
            if line.startswith(('||', '@@', '|')) or any(c in line for c in '^$*'):
                skipped += 1; continue    # other adblock syntax (regex, wildcards, cosmetic) -> skip
            parts = line.split()
            if parts[0] in ('0.0.0.0','127.0.0.1','::1','::'):
                entries = parts[1:]
            else:
                entries = parts if len(parts) == 1 else []
            for d in entries:
                d = norm(d)
                if '.' in d and ' ' not in d:
                    domains.add(d)
    if allow:
        before = len(domains); domains -= allow
        print(f'allowlisted      : {before - len(domains):,} removed ({len(allow):,} @@ rules)', file=sys.stderr)
    if skipped:
        print(f'skipped rules    : {skipped:,} (adblock syntax that a DNS hash list cannot express)', file=sys.stderr)

    listed = len(domains)
    domains = prune(domains)
    hashes = sorted(fnv(d.encode()) for d in domains)
    collisions = len(hashes) - len(set(hashes))
    uniq = sorted(set(hashes))                       # one entry per distinct hash
    if not uniq:
        print('!! no domains found', file=sys.stderr); sys.exit(1)
    blob = b''.join(h.to_bytes(HASH_BYTES, 'little') for h in uniq) if v1 else encode_v2(uniq)

    n, size = len(uniq), len(blob)
    print(f'source domains   : {listed:,}')
    print(f'redundant subdom.: {listed - len(domains):,} dropped (a listed parent already covers them)')
    print(f'hash entries     : {n:,}  ({HASH_BYTES*8}-bit, collisions {collisions})')
    print(f'format           : {"v1 (uncompressed, 40 bits/entry)" if v1 else f"v2 ({size * 8 / n:.1f} bits/entry)"}')
    print(f'file             : {size:,} bytes = {size / DATA_CAP * 100:.1f}% of the device partition')
    if size > DATA_CAP:
        print(f'!! too large for the device ({DATA_CAP:,} bytes max): use fewer or smaller sources', file=sys.stderr)
        sys.exit(1)
    with open(out, 'wb') as f:
        f.write(blob)
    print(f'written          : {out}')

if __name__ == '__main__':
    main()
