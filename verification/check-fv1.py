"""Author: chatgpt. Tie V2 registry entries to a successful Kani suite log."""
import hashlib, pathlib, re, tomllib
root = pathlib.Path(__file__).resolve().parents[1]
registry = tomllib.loads((root/'verification/FV1.toml').read_text())
properties = registry['properties']
log = (root/'evidence/fv1/kani.log').read_text()
summary = re.findall(r'Complete - (\d+) successfully verified harnesses, 0 failures, (\d+) total\.', log)
assert summary, 'no successful Kani suite summary'
passed, total = map(int, summary[-1])
assert passed == total == len(properties), 'registry/harness count mismatch'
required = {'statement','code_and_spec_mapping','code_version','tool','environment',
            'bounds','assumptions_and_uncovered','reproduce','latest_pass'}
ids = set()
for prop in properties:
    assert prop['level'] == 'V2' and prop['status'] == 'proved'
    assert prop['id'] not in ids
    ids.add(prop['id'])
    assert all(prop.get(key) for key in required), f'missing specification field: {prop["id"]}'
    name = prop['reproduce'].split()[-1]
    assert name in log, f'harness absent in successful proof log: {name}'
manifest = root/'evidence/fv1/source.sha256'
assert manifest.stat().st_size > 0
for line in manifest.read_text().splitlines():
    digest, name = line.split(maxsplit=1)
    assert hashlib.sha256((root/name).read_bytes()).hexdigest() == digest, f'stale proof source: {name}'
print(f'FV-1 registry: {total} V2 entries match successful suite')
