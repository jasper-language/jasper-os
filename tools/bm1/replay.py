#!/usr/bin/env python3
"""Recheck saved BM-1 evidence with the current verifier; never changes raw data.
Framebuffer existence is checked here; visual inspection is a separate step.
"""
import argparse
import hashlib
import json
import pathlib
import struct
from run import Assembly, decode, validate_log


def replay(root, boots, cpus):
    summary = json.loads((root/'summary.json').read_text())
    if not summary.get('pass') or len(summary['boots']) != boots or summary['cpus'] != cpus:
        raise ValueError('summary is not a successful run with the required scope')
    events = json.loads((root/'qmp-events.json').read_text())
    resets = [e for e in events if e['event'] == 'RESET']
    if len(resets) != boots or any(e['event'] == 'WATCHDOG' for e in events):
        raise ValueError('reset count or unexpected watchdog')
    if not all(e.get('data', {}).get('guest') for e in resets):
        raise ValueError('reset was not initiated by guest')
    serial = (root/'serial.log').read_bytes()
    starts = []
    at = 0
    while True:
        at = serial.find(b'[JSR-BOOT]', at)
        if at < 0:
            break
        starts.append(at)
        at += 1
    if len(starts) < boots:
        raise ValueError('missing serial boot markers')
    logs = {}
    for index, record in enumerate(summary['boots'], 1):
        data = (root/f'boot-{index:02}.udp.log').read_bytes()
        validate_log(data, cpus)
        if record['boot'] != index or record['reset_before'] != index-1:
            raise ValueError('boots are not consecutive')
        if len(data) != record['bytes'] or hashlib.sha256(data).hexdigest() != record['sha256']:
            raise ValueError('log does not match recorded bytes/hash')
        if serial[starts[index-1]:starts[index-1]+len(data)] != data:
            raise ValueError('serial/UDP mismatch')
        if record['nonce'] in logs:
            raise ValueError('duplicate boot nonce')
        logs[record['nonce']] = data
        screen = root/f'boot-{index:02}.ppm'
        if not screen.is_file() or screen.stat().st_size < 100:
            raise ValueError('missing framebuffer evidence')
    # Reconstruct every log from the actual saved Ethernet datagrams too.
    pending, complete = {}, set()
    with (root/'frames.bin').open('rb') as stream:
        while header := stream.read(4):
            if len(header) != 4:
                raise ValueError('truncated frame length')
            length, = struct.unpack('!I', header)
            if not 0 < length <= 65535:
                raise ValueError('invalid frame length')
            packet = stream.read(length)
            if len(packet) != length:
                raise ValueError('truncated frame')
            if packet[42:46] != b'BM1L':
                continue
            nonce = decode(packet)[3]
            if nonce not in logs or nonce in complete:
                raise ValueError('unknown or duplicated completed boot')
            assembly = pending.setdefault(nonce, Assembly())
            data = assembly.add(packet)
            if data is not None:
                if data != logs[nonce]:
                    raise ValueError('raw frame/log mismatch')
                complete.add(nonce)
                del pending[nonce]
    if pending or complete != set(logs):
        raise ValueError('incomplete raw-frame capture')
    print(f'Replay PASS: {boots} consecutive boots, {cpus} online CPUs, raw frames = UDP = serial; screenshots present')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=pathlib.Path)
    parser.add_argument('--boots', type=int, default=10)
    parser.add_argument('--cpus', type=int, default=1)
    args = parser.parse_args()
    replay(args.root, args.boots, args.cpus)
