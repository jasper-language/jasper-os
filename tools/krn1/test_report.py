"""Author: chatgpt. Negative evidence contracts, including fixed-seed drift mutations."""
import json
import pathlib
import random
import tempfile
import unittest
from report import audit

READY = '[JSR-SOAK] ready cpus=8 free_frames=100 objects=0 pending=0 heap=(1000, 900, 1, 1000)\n'
def progress(n, frames=100):
    return f'[JSR-SOAK] progress rounds={n} user_iterations={n*1500} free_frames={frames} objects=0 pending=0 heap=(1000, 900, 1, 1000) conserved=true\n'

class EvidenceContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.temp.name)
        self.state = dict(phase='complete', pass_=True, exit_code=37, requested_seconds=28800,
                          elapsed_seconds=28801, latest_progress=progress(2).strip())
        self.log = READY+progress(1)+progress(2)+'[JSR-SOAK] complete rounds=2 user_iterations=3000 conserved=true\n[JSR-EXIT] timing-only\n'
    def tearDown(self): self.temp.cleanup()
    def write(self):
        (self.path/'status.json').write_text(json.dumps(self.state))
        (self.path/'serial.log').write_text(self.log)
    def test_valid_final_requires_full_audit(self):
        self.write()
        self.assertFalse(audit(self.path)['accepted'])
        self.assertTrue(audit(self.path, True)['accepted'])
    def test_live_never_passes(self):
        self.state.update(phase='running', pass_=False, elapsed_seconds=12)
        self.write(); self.assertFalse(audit(self.path, True)['accepted'])
    def test_short_or_nonfinite_duration_rejected(self):
        for value in (10, float('nan'), float('inf'), -1, True):
            self.state['elapsed_seconds'] = value; self.write()
            with self.assertRaises(ValueError): audit(self.path, True)
    def test_missing_progress_and_restart_rejected(self):
        for log in (READY+progress(2), READY+self.log,
                    self.log.replace('[JSR-EXIT] timing-only\n', '')):
            self.log = log; self.write()
            with self.assertRaises(ValueError): audit(self.path, True)
    def test_fixed_seed_resource_drift_cannot_hide_behind_true_flag(self):
        rng = random.Random(0xb001)
        for _ in range(64):
            self.state['latest_progress'] = progress(2, rng.randrange(101, 10000)).strip()
            self.write()
            with self.assertRaises(ValueError): audit(self.path, True)
    def test_raw_failure_not_masked_by_successful_status(self):
        self.log += '[JSR-PANIC] unexpected\n'; self.write()
        with self.assertRaises(ValueError): audit(self.path, True)

    def test_progress_after_completion_or_early_exit_rejected(self):
        for log in (READY+progress(1)+'[JSR-SOAK] complete rounds=1 user_iterations=1500 conserved=true\n'+progress(2)+'[JSR-EXIT] timing-only\n',
                    READY+'[JSR-EXIT] success\n'+progress(1)+progress(2)+'[JSR-SOAK] complete rounds=2 user_iterations=3000 conserved=true\n'):
            self.log = log; self.write()
            with self.assertRaises(ValueError): audit(self.path, True)
