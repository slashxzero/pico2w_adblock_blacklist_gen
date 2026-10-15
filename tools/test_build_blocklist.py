import pathlib
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

from build_blocklist import DATA_CAP, HASH_BYTES, fnv, prune

TOOL = pathlib.Path(__file__).with_name('build_blocklist.py')


def decode_v2(data: bytes) -> list:
    """Independent reader of format 2 (mirrors src/blocklist.c)."""
    magic, hb, b, k, zero, count, stream_bits, crc = struct.unpack_from('<4sBBBBIII', data)
    assert magic == b'PBL2' and hb == 40 and zero == 0
    nb = 1 << b
    table = struct.unpack_from(f'<{nb + 1}I', data, 20)
    stream = data[20 + 4 * (nb + 1):]
    assert len(stream) == (stream_bits + 7) // 8 and zlib.crc32(data[20:]) == crc
    bits = ''.join(f'{byte:08b}' for byte in stream)
    out = []
    for bucket in range(nb):
        pos, end, prev = table[bucket], table[bucket + 1], -1
        while pos < end:
            q = 0
            while bits[pos] == '1':
                q += 1; pos += 1
            pos += 1
            rem = int(bits[pos:pos + k], 2) if k else 0
            pos += k
            prev += ((q << k) | rem) + 1
            out.append((bucket << (hb - b)) | prev)
        assert pos == end
    assert len(out) == count
    return out


def build(root, text, *flags):
    source, output = root / 'hosts', root / 'blocklist.bin'
    source.write_text(text, encoding='utf-8')
    run = subprocess.run([sys.executable, str(TOOL), *flags, str(output), str(source)],
                         capture_output=True, text=True)
    return run, output


class BuildBlocklistTests(unittest.TestCase):
    def test_hosts_line_includes_every_domain(self):
        with tempfile.TemporaryDirectory() as d:
            run, out = build(pathlib.Path(d), '0.0.0.0 ads.example.com tracker.example.com # comment\n'
                                              '127.0.0.1 metrics.example.com\n')
            self.assertEqual(run.returncode, 0, run.stderr)
            expected = sorted(fnv(x.encode()) for x in ('ads.example.com', 'tracker.example.com', 'metrics.example.com'))
            self.assertEqual(decode_v2(out.read_bytes()), expected)

    def test_v1_format_is_plain_sorted_hashes(self):
        with tempfile.TemporaryDirectory() as d:
            run, out = build(pathlib.Path(d), 'b.example.com\na.example.org\n', '--v1')
            data = out.read_bytes()
            hashes = [int.from_bytes(data[i:i + HASH_BYTES], 'little') for i in range(0, len(data), HASH_BYTES)]
            self.assertEqual(hashes, sorted(fnv(x.encode()) for x in ('b.example.com', 'a.example.org')))

    def test_redundant_subdomains_are_dropped(self):
        self.assertEqual(prune({'example.com', 'ads.example.com', 'x.y.example.com', 'other.net', 'a.b.co.uk', 'b.co.uk'}),
                         {'example.com', 'other.net', 'b.co.uk'})
        self.assertEqual(prune({'ads.example.com', 'cdn.example.com'}), {'ads.example.com', 'cdn.example.com'})   # parent not listed

    def test_large_list_round_trips_and_is_compressed(self):
        domains = [f'host{i}.example{i % 997}.com' for i in range(50000)]
        with tempfile.TemporaryDirectory() as d:
            run, out = build(pathlib.Path(d), '\n'.join(domains) + '\n')
            data = out.read_bytes()
            self.assertEqual(decode_v2(data), sorted({fnv(x.encode()) for x in domains}))
            self.assertLess(len(data) * 8 / len(domains), 28)              # ~27 at 50k entries, vs 40 uncompressed

    def test_too_large_is_refused(self):
        n = DATA_CAP // HASH_BYTES + 10                                    # v1 cannot hold it
        with tempfile.TemporaryDirectory() as d:
            run, out = build(pathlib.Path(d), ''.join(f'h{i}.example.net\n' for i in range(n)), '--v1')
            self.assertEqual(run.returncode, 1)
            self.assertIn('too large', run.stderr)
            self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main()
