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
# 能力集合容量是权威来源：登记表不得出现无法表示的 ID（也不再假定 64 位掩码）。
sysset=(root/'kernel-core/src/syscall_set.rs').read_text()
match=re.search(r'pub const MAX_IDS: usize = (\d+);',sysset)
assert match, 'SyscallSet capacity constant is missing'
max_ids=int(match.group(1))
for row in reg.values():
    if row[1]=='op' and int(row[0])>=max_ids:
        raise SystemExit(f'operation {row[0]} exceeds SyscallSet capacity {max_ids}: widen the set and ABI first')
source=(root/'kernel/src/syscall/mod.rs').read_text()
# 兼容两种分发表形状：旧的多 ID `A | B => err(...)` 与当前「一 ID 一个闭包」的宏展开。
arms=re.findall(r'((?:SYSTEM_[A-Z0-9_]+\s*\|\s*)*SYSTEM_[A-Z0-9_]+)\s*=>[^\n]*?err\(SYSTEM_ERROR_UNSUPPORTED\)',source)
unsupported={name.strip() for arm in arms for name in arm.split('|')}
# ID 43 crossed the ABI 2.0.0 boundary from a stable reserved slot to an
# executable operation. The remaining reserved IDs must still fail closed.
assert reg[43][3]=='3', 'ID 43 must use the executable v3 contract'
for num in range(37,43):
    constant=reg[num][2].upper().replace('.','_')
    assert constant in unsupported, f'reserved handler must explicitly return unsupported: {constant}'
assert 'SYSTEM_TASK_SYSCALLS_SET => |_e: &AbiEntry, a: &SyscallArgs, task_id: u64|' in source
ring=(root/'kernel/src/ring.rs').read_text()
assert 'extension_abi::check_sqe_flags(sqe.flags)' in ring
assert 'FlagError::Unsupported) => return Err(err(SYSTEM_ERROR_UNSUPPORTED))' in ring
shape=(root/'kernel-core/src/extension_abi.rs').read_text()
for constant,size in [('HEADER_BYTES',8),('SEGMENT_BYTES',32),('SERVICE_HEADER_BYTES',8),('SYSCALL_SET_V2_BYTES',40),('BORROW_BYTES',48),('CONTROL_BYTES',32)]:
    assert f'pub const {constant}: usize = {size};' in shape
assert 'SQE_REGISTERED_BUFFER: u32 = 1 << 31;' in shape
print('ABI-R reserved IDs/display names/wire constants/capacity gate: PASS')
