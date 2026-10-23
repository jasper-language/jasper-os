#!/usr/bin/env python3
"""BM-1 VM acceptance: persistent UEFI guest, real RTL8139 frames, CF9 resets.
Only loopback sockets and image files under the output directory are used.
"""
import argparse, hashlib, json, os, pathlib, select, shutil, socket, struct, subprocess, time


def fnv(data):
    h = 2166136261
    for b in data:
        h = ((h ^ b) * 16777619) & 0xffffffff
    return h


def decode(frame):
    if len(frame) < 66 or frame[12:14] != b'\x08\x00':
        raise ValueError('not IPv4/Ethernet')
    ip = frame[14:34]
    if ip[0] != 0x45 or ip[9] != 17 or ip[6:8] != b'\0\0':
        raise ValueError('unsupported IP header')
    words = struct.unpack('!10H', ip)
    total = sum(words)
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    if total != 65535:
        raise ValueError('IP checksum')
    length = struct.unpack_from('!H', ip, 2)[0]
    sport, dport, ulen, cs = struct.unpack_from('!4H', frame, 34)
    if (sport, dport) != (5555, 5555) or ulen != length-20 or len(frame) < 14+length:
        raise ValueError('UDP length/ports')
    data = frame[42:14+length]
    magic, offset, size, digest, nonce = struct.unpack_from('!4sIIIQ', data)
    payload = data[24:]
    if magic != b'BM1L' or not 0 < size <= 8*1024*1024 or not payload or offset % 1024 or len(payload) != min(1024, size-offset):
        raise ValueError('log header/bounds')
    return offset, size, digest, nonce, payload


class Assembly:
    def __init__(self):
        self.parts, self.meta = {}, None
        self.received_bytes = 0

    def add(self, packet):
        offset, size, digest, nonce, payload = decode(packet)
        if self.meta is not None and self.meta != (size, digest, nonce):
            raise ValueError('mixed log generations')
        self.meta = size, digest, nonce
        if offset in self.parts:
            raise ValueError('duplicate offset')
        self.parts[offset] = payload
        self.received_bytes += len(payload)
        if self.received_bytes == size:
            data = b''.join(self.parts[i] for i in range(0, size, 1024))
            if fnv(data) != digest:
                raise ValueError('log hash')
            return data


def validate_log(data, cpus):
    if b'[BM1] selftest=PASS framebuffer=true' not in data or b'[JSR-EXIT] failure' in data or b'user_programs=absent' in data:
        raise ValueError('kernel selftest or framebuffer failure')
    if not (b'[JSR-EXIT] success' in data or b'[JSR-EXIT] timing-only' in data):
        raise ValueError('missing terminal kernel result')
    if f'[JSR-SMP] start present={cpus} online={cpus} failed=0 '.encode() not in data:
        raise ValueError('configured CPUs did not all come online')
    if f'[JSR-SMP] summary cpus={cpus} online={cpus} '.encode() not in data:
        raise ValueError('missing multicore selftest summary')


class QMP:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(10)
        self.sock.connect(str(path))
        self.file = self.sock.makefile('rb')
        self.events = []
        self.read()
        self.command('qmp_capabilities')

    def read(self):
        value = json.loads(self.file.readline())
        if 'event' in value:
            self.events.append(value)
        return value

    def command(self, cmd, **args):
        self.sock.sendall(json.dumps({'execute': cmd, 'arguments': args}).encode()+b'\n')
        while True:
            response = self.read()
            if 'error' in response:
                raise RuntimeError(response)
            if 'return' in response:
                return response['return']


def run(args):
    out = pathlib.Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8*1024*1024)
    udp.bind(('127.0.0.1', 0))
    port = udp.getsockname()[1]
    udp.setblocking(False)
    vars_file = out/'OVMF_VARS.fd'
    shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', vars_file)
    (out/'blank.img').write_bytes(bytes(1024*1024))
    qpath = out/'qmp.sock'
    cmd = ['qemu-system-x86_64', '-accel', 'tcg', '-m', '256M', '-smp', str(args.cpus),
           '-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
           '-drive', f'if=pflash,format=raw,file={vars_file}',
           '-drive', f'format=raw,file={pathlib.Path(args.image).resolve()},snapshot=on',
           '-device', 'virtio-rng-pci', '-device', 'virtio-net-pci,netdev=n0', '-netdev', 'user,id=n0',
           '-device', 'virtio-blk-pci,drive=d1', '-drive', f'if=none,id=d1,format=raw,file={out}/blank.img',
           '-device', 'rtl8139,netdev=logs', '-netdev', f'socket,id=logs,udp=127.0.0.1:{port},localaddr=127.0.0.1:0',
           '-device', 'ib700', '-watchdog-action', 'reset',
           '-boot', 'order=c,strict=on', '-display', 'none', '-serial', f'file:{out}/serial.log',
           '-qmp', f'unix:{qpath},server=on,wait=off']
    icount = os.environ.get('BM1_ICOUNT')
    if icount is not None:
        if not icount.isdigit() or not 0 <= int(icount) <= 10:
            raise ValueError('BM1_ICOUNT must be a shift from 0 to 10')
        cmd[cmd.index('tcg')] = 'tcg,thread=single'
        cmd += ['-icount', f'shift={icount},sleep=off']
    (out/'command.json').write_text(json.dumps(cmd, indent=2))
    summary = {'scope': 'QEMU/OVMF VM; not physical PC validation', 'cpus': args.cpus, 'boots': [], 'pass': False}
    start = time.monotonic()
    keep = []
    if icount is None and os.environ.get('JASPER_KEEP_AWAKE') == '1':
        for cpu in sorted(os.sched_getaffinity(0)):
            keep.append(subprocess.Popen(['taskset', '-c', str(cpu), 'chrt', '-i', '0', 'sh', '-c', 'while :; do :; done']))
    proc = subprocess.Popen(cmd, stdout=(out/'qemu.stdout').open('wb'), stderr=(out/'qemu.stderr').open('wb'))
    qmp = None
    try:
        while not qpath.exists():
            if proc.poll() is not None or time.monotonic()-start > 15:
                raise RuntimeError('QEMU startup failed')
            time.sleep(.05)
        qmp = QMP(qpath)
        assembly, boot_start, reset_start = Assembly(), time.monotonic(), 0
        reset_count = 0
        seen_nonces = set()
        next_poll = 0.0
        serial = b''
        while len(summary['boots']) < args.boots:
            if proc.poll() is not None:
                raise RuntimeError('QEMU exited before completion')
            if time.monotonic() >= next_poll:
                next_poll = time.monotonic()+0.1
                serial = (out/'serial.log').read_bytes()
                if not args.hang and b'[BM1] udp=FAIL' in serial:
                    raise RuntimeError('guest upload failed; inspect kernel terminal result')
                # query-status drains QMP events and records actual guest RESETs.
                qmp.command('query-status')
                if not args.hang and any(e.get('event') == 'WATCHDOG' for e in qmp.events[reset_start:]):
                    raise RuntimeError('unexpected watchdog during functional boot')
                resets = [e for e in qmp.events[reset_start:] if e.get('event') == 'RESET']
                reset_start = len(qmp.events)
                for event in resets:
                    reset_count += 1
                    if args.hang:
                        serial = (out/'serial.log').read_bytes()
                        if b'[BM1] injected_hang' not in serial or not any(e.get('event') == 'WATCHDOG' for e in qmp.events):
                            raise RuntimeError('reset without injected hang and watchdog event')
                        summary['boots'].append({'watchdog_reset': True, 'event': event})
                        break
            if args.hang and summary['boots']:
                break
            ready, _, _ = select.select([udp], [], [], .01)
            if ready:
                packet = udp.recv(65535)
                with (out/'frames.bin').open('ab') as f:
                    f.write(struct.pack('!I', len(packet))+packet)
                # OVMF may emit ARP/DHCP while enumerating the NIC.
                # Ignore unrelated traffic; missing/corrupted log frames time out.
                if packet[42:46] != b'BM1L':
                    continue
                first_frame = assembly.meta is None
                data = assembly.add(packet)
                if first_frame:
                    # TX begins only after the terminal text was rendered. Capture
                    # now, before whole-log hashing allows the guest to reset.
                    n = len(summary['boots'])+1
                    qmp.command('stop')
                    qmp.command('screendump', filename=str(out/f'boot-{n:02}.ppm'))
                    qmp.command('cont')
                if data is not None:
                    n = len(summary['boots'])+1
                    nonce = assembly.meta[2]
                    if nonce in seen_nonces or reset_count != n-1:
                        raise ValueError('stale boot or missing preceding reset')
                    seen_nonces.add(nonce)
                    (out/f'boot-{n:02}.udp.log').write_bytes(data)
                    validate_log(data, args.cpus)
                    # Source bytes must really match serial, not a host-generated log.
                    serial = (out/'serial.log').read_bytes()
                    begin = serial.rfind(b'[JSR-BOOT]')
                    if serial.count(b'[JSR-BOOT]') != n or begin < 0 or serial[begin:begin+len(data)] != data:
                        raise RuntimeError('UDP/serial mismatch')
                    summary['boots'].append({'boot': n, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'reset_before': reset_count, 'nonce': nonce})
                    print(f'boot {n}/{args.boots}: kernel functional PASS, UDP {len(data)} bytes identical, framebuffer captured', flush=True)
                    assembly, boot_start = Assembly(), time.monotonic()
            if time.monotonic()-boot_start > args.timeout:
                raise TimeoutError(f'boot/log deadline; received={assembly.received_bytes} expected={assembly.meta}; incomplete log is not PASS')
        # Completion includes the final guest reset, not merely a sent log.
        if not args.hang:
            deadline = time.monotonic()+20
            while sum(e.get('event') == 'RESET' for e in qmp.events) < args.boots:
                if time.monotonic() > deadline:
                    raise TimeoutError('missing guest reset')
                qmp.command('query-status')
                time.sleep(.02)
            summary['reset_events'] = sum(e.get('event') == 'RESET' for e in qmp.events)
        if not args.hang and any(e.get('event') == 'WATCHDOG' for e in qmp.events):
            raise RuntimeError('unexpected watchdog recovery interrupts consecutive successful boots')
        summary['pass'] = True
    finally:
        if qmp:
            (out/'qmp-events.json').write_text(json.dumps(qmp.events, indent=2))
            try:
                qmp.command('quit')
            except (OSError, ValueError):
                pass
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        for process in keep:
            process.terminate()
        for process in keep:
            process.wait()
        udp.close()
        summary['elapsed_seconds'] = round(time.monotonic()-start, 2)
        (out/'summary.json').write_text(json.dumps(summary, indent=2))
    print(f'BM-1 VM PASS: {out}', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--boots', type=int, default=10)
    parser.add_argument('--cpus', type=int, default=1)
    parser.add_argument('--timeout', type=int, default=300)
    parser.add_argument('--hang', action='store_true')
    a = parser.parse_args()
    if a.boots < 1 or a.cpus < 1 or a.timeout < 1:
        parser.error('boots, cpus and timeout must be positive')
    run(a)
