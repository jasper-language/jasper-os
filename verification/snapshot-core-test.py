"""Preserve the exact built core unit-test ELF before execution; never infer identity later."""
import hashlib,json,pathlib,shutil,sys
root=pathlib.Path(__file__).resolve().parents[1]
run=pathlib.Path(sys.argv[1]).resolve()
artifacts=[]
for line in (run/'core-build.jsonl').read_text().splitlines():
    try: e=json.loads(line)
    except ValueError: continue
    if e.get('reason')=='compiler-artifact' and e.get('target',{}).get('name')=='kernel_core' and e.get('profile',{}).get('test') and e.get('executable'):
        artifacts.append(pathlib.Path(e['executable']).resolve())
assert len(artifacts)==1,artifacts
binary=artifacts[0];binary.relative_to(root/'target')
copy=run/'core-test-binary';shutil.copy2(binary,copy)
digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert digest(binary)==digest(copy)
(run/'core-test-binary.sha256').write_text(f'{digest(copy)}  core-test-binary\n')
(run/'core-test-origin.txt').write_text(str(binary)+'\n')
print('Exact pre-run core test binary preserved:',digest(copy))
