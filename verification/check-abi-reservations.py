"""ABI-R reservation gate. Rust shape/decoder assertions run separately inside VM."""
from pathlib import Path
import re
root=Path(__file__).resolve().parents[1]
reg={}
for line in (root/'abi/system-ids.txt').read_text().splitlines():
    if not line or line.startswith('#'): continue
    fields=line.split('\t'); reg[int(fields[0])]=fields
for num,name in {37:'system.memory.buffer.create',38:'system.memory.buffer.destroy',39:'system.execution.restricted.create',40:'system.task.interrupt.send',41:'system.memory.dma.map',42:'system.io.segment.submit',43:'system.task.syscalls.set'}.items():
    row=reg[num]; assert row[1]=='op' and row[2]==name and row[5] and row[6]
source=(root/'kernel/src/syscall/mod.rs').read_text()
for row in reg.values():
    if row[1]=='op' and int(row[0])>=64:
        raise SystemExit('Live v1 mask cannot grant operation >=64: implement v2 admission before adding it')
arms=re.findall(r'((?:SYSTEM_[A-Z0-9_]+\s*\|\s*)*SYSTEM_[A-Z0-9_]+)\s*=>\s*err\(SYSTEM_ERROR_UNSUPPORTED\)',source)
unsupported={name.strip() for arm in arms for name in arm.split('|')}
for num in range(37,44):
    constant=reg[num][2].upper().replace('.','_')
    assert constant in unsupported, f'reserved handler must explicitly return unsupported: {constant}'
ring=(root/'kernel/src/ring.rs').read_text()
assert 'extension_abi::check_sqe_flags(sqe.flags)' in ring
assert 'FlagError::Unsupported) => return Err(err(SYSTEM_ERROR_UNSUPPORTED))' in ring
shape=(root/'kernel-core/src/extension_abi.rs').read_text()
for constant,size in [('HEADER_BYTES',8),('SEGMENT_BYTES',32),('SERVICE_HEADER_BYTES',8),('SYSCALL_SET_V2_BYTES',40),('BORROW_BYTES',48),('CONTROL_BYTES',32)]:
    assert f'pub const {constant}: usize = {size};' in shape
assert 'SQE_REGISTERED_BUFFER: u32 = 1 << 31;' in shape
print('ABI-R reserved IDs/display names/wire constants/v1 range gate: PASS')
