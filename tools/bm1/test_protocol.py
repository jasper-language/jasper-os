"""Fixed-seed protocol properties; smallest failing input is printed by subTest.
These tests validate the host verifier, not a proof of hardware or the Rust TX.
"""
import random
import struct
import unittest
from run import Assembly, decode, fnv, validate_log


def packets(data, nonce=1):
    result = []
    for offset in range(0, len(data), 1024):
        payload = struct.pack('!4sIIIQ', b'BM1L', offset, len(data), fnv(data), nonce) + data[offset:offset+1024]
        udp = struct.pack('!4H', 5555, 5555, len(payload)+8, 0) + payload
        ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(udp), 0, 0, 64, 17, 0, bytes([192,0,2,2]), bytes([192,0,2,1])))
        n = sum(struct.unpack('!10H', ip))
        while n >> 16:
            n = (n & 65535) + (n >> 16)
        struct.pack_into('!H', ip, 10, (~n)&65535)
        result.append(b'\xff'*6 + bytes([2,0,0,0,0,1])+b'\x08\x00'+ip+udp)
    return result


class ProtocolProperties(unittest.TestCase):
    def test_fixed_seed_roundtrip_reorder_loss_corruption(self):
        rng = random.Random(0xB001)
        for length in [1, 1023, 1024, 1025, 4096] + [rng.randint(1, 20000) for _ in range(40)]:
            with self.subTest(length=length):
                data = rng.randbytes(length)
                ps = packets(data)
                shuffled = ps.copy()
                rng.shuffle(shuffled)
                a = Assembly()
                values = [a.add(p) for p in shuffled]
                self.assertEqual(values[-1], data)
                self.assertTrue(all(v is None for v in values[:-1]))
                # Every proper prefix of a complete packet set must remain incomplete.
                for missing in range(len(ps)):
                    a = Assembly()
                    for i, p in enumerate(ps):
                        if i != missing:
                            self.assertIsNone(a.add(p))
                corrupt = list(ps)
                p = bytearray(corrupt[-1]); p[-1] ^= 1; corrupt[-1] = p
                with self.assertRaisesRegex(ValueError, 'log hash'):
                    a = Assembly()
                    for p in corrupt:
                        a.add(p)

    def test_duplicate_and_mixed_boot_rejected(self):
        ps = packets(b'a'*2048, 1)
        a = Assembly(); a.add(ps[0])
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            a.add(ps[0])
        with self.assertRaisesRegex(ValueError, 'mixed'):
            a.add(packets(b'a'*2048, 2)[1])

    def test_functional_failures_missing_users_and_offline_cpus_rejected(self):
        good = (b'[JSR-EXIT] timing-only bench_timing_failed=1\n'
                b'[BM1] selftest=PASS framebuffer=true\n'
                b'[JSR-SMP] start present=4 online=4 failed=0 source=acpi.madt\n'
                b'[JSR-SMP] summary cpus=4 online=4 checks=20 failed=0\n')
        validate_log(good, 4)
        cases = [good.replace(b'timing-only', b'failure'),
                 good.replace(b'framebuffer=true', b'framebuffer=false'),
                 good+b'user_programs=absent',
                 good.replace(b'online=4', b'online=1'),
                 good.replace(b'[JSR-EXIT]', b'[OTHER]')]
        for bad in cases:
            with self.subTest(log=bad), self.assertRaises(ValueError):
                validate_log(bad, 4)

    def test_malformed_frames_rejected(self):
        good = packets(b'abc')[0]
        for n in range(len(good)):
            with self.subTest(truncate=n), self.assertRaises((ValueError, struct.error)):
                decode(good[:n])
        for at in [12, 14, 16, 20, 23, 24, 34, 36, 38, 42, 46, 50]:
            bad = bytearray(good); bad[at] ^= 0x80
            with self.subTest(offset=at), self.assertRaises((ValueError, struct.error)):
                decode(bad)


if __name__ == '__main__':
    unittest.main()
