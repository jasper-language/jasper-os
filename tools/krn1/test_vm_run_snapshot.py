"""Author: chatgpt. A public script edit must not replay an in-flight command.
Uses fake SSH/rsync, never changes the real wrapper or contacts another machine.
"""
import os
import pathlib
import subprocess
import tempfile
import time
import unittest


class ShellSnapshotTests(unittest.TestCase):
    def test_edit_public_wrapper_during_command_does_not_replay(self):
        fixture = pathlib.Path(__file__).with_name('vm_run_fixture.sh').read_text()
        with tempfile.TemporaryDirectory(prefix='jasper-snapshot-test-') as directory:
            root = pathlib.Path(directory)
            public = root/'wrapper.sh'
            public.write_text(fixture)
            (root/'project').mkdir()
            binary = root/'bin'
            binary.mkdir()
            ssh = binary/'ssh'
            ssh.write_text('''#!/usr/bin/env python3
import os,pathlib,sys,time
root=pathlib.Path(os.environ['JASPER_SNAPSHOT_TEST_STATE'])
if 'nice -n' in sys.argv[-1]:
    with (root/'executions').open('a') as output: output.write('run\\n')
    (root/'started').touch()
    deadline=time.monotonic()+15
    while not (root/'release').exists():
        if time.monotonic()>deadline: sys.exit(95)
        time.sleep(0.01)
''')
            ssh.chmod(0o755)
            rsync = binary/'rsync'
            rsync.write_text('#!/bin/sh\nexit 0\n')
            rsync.chmod(0o755)
            env = dict(os.environ, PATH=str(binary)+os.pathsep+os.environ['PATH'],
                       JASPER_SNAPSHOT_TEST_STATE=str(root))
            process = subprocess.Popen(['bash', str(public), str(root/'project'), 'true'],
                                       env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic()+15
                while not (root/'started').exists():
                    if process.poll() is not None or time.monotonic()>deadline:
                        self.fail('wrapper never reached the in-flight command')
                    time.sleep(0.01)
                # Deliberately change byte offsets while the child is waiting.
                public.write_text('# changed public script offsets\n'*8192 + fixture)
                (root/'release').touch()
                stdout, stderr = process.communicate(timeout=15)
                self.assertEqual(process.returncode, 0, (stdout, stderr))
                self.assertEqual((root/'executions').read_text(), 'run\n')
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
