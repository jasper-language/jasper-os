//! 内核对象、权限与句柄表（Handle/Rights 是 jasper-os 访问资源的**唯一**途径）。
//!
//! # 职责
//! * [`Rights`]：全系统统一的一张权限位表（命名约定：`READ WRITE EXECUTE WAIT CONTROL`）
//! * [`ObjectId`] / [`ObjectType`] / [`KernelObject`]：对象身份与类型
//! * [`HandleTable`]：每个进程一张的句柄表——槽位 + **世代计数**，关闭后的旧句柄
//!   即使槽位被复用也会被拒绝（防 ABA）
//! * [`ObjectManager`]：分配永不复用的对象 ID
//!
//! # 为什么这样设计
//! * 句柄值 = `(世代 << 16) | (槽位 + 1)`：0 永远不是合法句柄（可作空值）；
//!   同一槽位每次释放世代 +1，旧值与新值必然不同。世代即将回绕的槽位**永久退役**，
//!   以空间换绝对的「关闭后不可复用」保证。
//! * 权限只能衰减不能放大（[`HandleTable::restrict`]），与 capability 模型一致。
//! * 句柄表对值类型 `V` 泛型：今天存 [`ObjectRef`]，将来可存真实对象引用，表的机制不变。
//! * 错误是带规范名的枚举（`system.handle.error.*`），不是整数 errno。

use core::fmt;
use core::sync::atomic::Ordering;

use crate::sync::Atomic64;

/// 句柄上的权限位掩码。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rights(u32);

impl Rights {
    /// 无权限。
    pub const NONE: Rights = Rights(0);
    /// 读取对象状态或数据。
    pub const READ: Rights = Rights(1 << 0);
    /// 修改对象状态或写入数据。
    pub const WRITE: Rights = Rights(1 << 1);
    /// 执行（代码映射、程序装载）。
    pub const EXECUTE: Rights = Rights(1 << 2);
    /// 等待对象的信号。
    pub const WAIT: Rights = Rights(1 << 3);
    /// 控制对象生命周期与属性（发信号、销毁、改保护）。
    pub const CONTROL: Rights = Rights(1 << 4);
    /// 允许复制该句柄（`system.handle.duplicate`）。M4.0 规范 v0.6 §3.1。
    pub const DUPLICATE: Rights = Rights(1 << 5);
    /// 允许把该句柄经 Channel 传给其他进程。M4.0 规范 v0.6 §3.1。
    pub const TRANSFER: Rights = Rights(1 << 6);
    /// 映射对象的寄存器 / 内存窗口（DRV-1C 的设备句柄使用；不含 READ 的隐式含义）。
    /// Map the object's register window into the caller's address space.
    pub const MAP: Rights = Rights(1 << 7);
    /// 全部已定义的权限。
    ///
    /// ABI 说明：各位的数值一经发布永不改变，新权限只能占用新的位。
    pub const ALL: Rights = Rights(0b1111_1111);

    /// 位名表（按位序），用于格式化输出。
    const NAMES: [(Rights, &'static str); 8] = [
        (Rights::READ, "READ"),
        (Rights::WRITE, "WRITE"),
        (Rights::EXECUTE, "EXECUTE"),
        (Rights::WAIT, "WAIT"),
        (Rights::CONTROL, "CONTROL"),
        (Rights::DUPLICATE, "DUPLICATE"),
        (Rights::TRANSFER, "TRANSFER"),
        (Rights::MAP, "MAP"),
    ];

    /// 由原始位构造；未定义的位被丢弃（不允许凭空造出未知权限）。
    pub const fn from_bits_truncate(bits: u32) -> Rights {
        Rights(bits & Rights::ALL.0)
    }

    /// 原始位。
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// 是否包含 `other` 的全部位。
    pub const fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }

    /// 并集。
    pub const fn union(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }

    /// 交集。
    pub const fn intersect(self, other: Rights) -> Rights {
        Rights(self.0 & other.0)
    }

    /// 差集（`self` 去掉 `other` 的位）。
    pub const fn difference(self, other: Rights) -> Rights {
        Rights(self.0 & !other.0)
    }

    /// 是否为空。
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// 输出形如 `WAIT|CONTROL`；空集输出 `NONE`。
impl fmt::Display for Rights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("NONE");
        }
        let mut first = true;
        for (bit, name) in Rights::NAMES {
            if self.contains(bit) {
                if !first {
                    f.write_str("|")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Rights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Rights({})", self)
    }
}

/// 单调递增、永不复用的 ID 分配器（原子操作，可在中断上下文使用）。
///
/// 从 1 开始，0 保留为「无」。对象 ID、追踪事件序号、异步请求号都用它。
/// 可分配的 ID 为 `1..=u64::MAX`；用尽后 [`allocate`](Self::allocate) 永远返回 `None`——
/// **绝不回绕**（回绕会让新对象与旧对象同号，破坏「永不复用」）。
/// 内部用比较交换循环推进：内部计数 0 表示「已用尽」，因此用尽状态也是原子可见的。
/// Monotonic, never-reused ID allocator; returns `None` once exhausted instead of wrapping.
pub struct IdAllocator {
    /// 下一个要分配的 ID；0 = 已用尽。
    next: Atomic64,
}

/// ID 已用尽（`system.object.error.ids_exhausted` 语义；调用方据此拒绝创建）。
/// The ID space is exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdExhausted;

impl IdAllocator {
    /// 新建，从 1 开始分配。
    pub const fn new() -> Self {
        IdAllocator { next: Atomic64::new(1) }
    }

    /// 新建，从 `first` 开始分配（用于演练耗尽路径；`first == 0` 视为已用尽）。
    /// Start at `first` (exercises exhaustion; `0` means already exhausted).
    pub const fn starting_at(first: u64) -> Self {
        IdAllocator { next: Atomic64::new(first) }
    }

    /// 取下一个 ID；已用尽时返回 `None`，且之后永远返回 `None`。
    /// Next ID, or `None` once `u64::MAX` has been handed out.
    pub fn allocate(&self) -> Option<u64> {
        let mut cur = self.next.load(Ordering::Relaxed);
        loop {
            if cur == 0 {
                return None;
            }
            // u64::MAX 发出后下一个值回到 0 = 「已用尽」哨兵
            let new = cur.wrapping_add(1);
            match self.next.compare_exchange_weak(cur, new, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return Some(cur),
                Err(seen) => cur = seen,
            }
        }
    }

    /// 是否已用尽。
    pub fn exhausted(&self) -> bool {
        self.next.load(Ordering::Relaxed) == 0
    }

    /// 已分配的个数（从 1 起算；用尽时为 `u64::MAX`）。
    pub fn allocated(&self) -> u64 {
        match self.next.load(Ordering::Relaxed) {
            0 => u64::MAX,
            n => n - 1,
        }
    }
}

impl Default for IdAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// 全局唯一的对象标识（永不复用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectId(pub u64);

/// 内核对象类型。名字与命名约定 的类型末段一致（PascalCase）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectType {
    /// 事件（`system.wait` 领域）。
    Event,
    /// 定时器（`system.time` 领域）。
    Timer,
    /// 异步提交/完成队列（`system.async.ring` 后端）。
    Ring,
    /// 地址空间（`system.memory` 领域）。
    AddressSpace,
    /// IPC 通道（`system.channel` 领域）。
    Channel,
    /// 线程/执行流（`system.task` 领域）。
    Task,
    /// 进程：地址空间 + 资源容器 + 生命周期（`system.process` 领域）。
    Process,
    /// 设备：启动期 PCI 设备表中的一项（`system.device` 领域）。关闭句柄不销毁设备表项。
    /// Device: one entry of the boot-time PCI table; closing a handle does not destroy it.
    Device,
    /// 设备中断：一个 MSI-X 表项到某个处理器向量的绑定（`system.device.interrupt` 领域）。
    /// v1 不可经消息转移：绑定归属创建它的进程，关闭即解绑。
    /// Device interrupt: one MSI-X entry bound to a processor vector; not transferable in v1.
    Interrupt,
}

impl ObjectType {
    /// v1 是否允许经 Channel 传递：只有「叶子对象」——自身不持有句柄、
    /// 也不强引用非叶子对象——可以传递。Channel 端点、Ring、Process、AddressSpace 在 v1 不可传递
    /// （阶段性限制，放宽前须证明仍保持强引用图无环）。
    ///
    /// **范围说明**：设计约束中的叶子对象还包括「共享内存（Memory）对象」，但该对象类型**尚未实现**
    /// （本枚举里没有它）。[`ObjectType::AddressSpace`] 是整套地址翻译、属于进程内部的非叶子资源，
    /// **不是**共享内存对象，因此不可传递，也不得用它代替共享内存。共享内存对象实现时会作为新的
    /// 叶子类型加入本函数，不改变其余类型的判定。
    /// Whether v1 IPC may transfer this type (leaf objects only). The shared-memory leaf object is not
    /// implemented yet; `AddressSpace` is not a substitute for it and stays non-transferable.
    pub const fn is_transferable_v1(self) -> bool {
        matches!(self, ObjectType::Event | ObjectType::Timer | ObjectType::Task | ObjectType::Device)
    }

    /// 类型名（输出与元数据用）。
    pub const fn type_name(self) -> &'static str {
        match self {
            ObjectType::Event => "Event",
            ObjectType::Timer => "Timer",
            ObjectType::Ring => "Ring",
            ObjectType::AddressSpace => "AddressSpace",
            ObjectType::Channel => "Channel",
            ObjectType::Task => "Task",
            ObjectType::Process => "Process",
            ObjectType::Device => "Device",
            ObjectType::Interrupt => "Interrupt",
        }
    }
}

/// 一切内核对象的共同接口：有身份、有类型。
pub trait KernelObject {
    /// 对象 ID。
    fn id(&self) -> ObjectId;
    /// 对象类型。
    fn object_type(&self) -> ObjectType;
    /// 类型名（默认取自类型）。
    fn type_name(&self) -> &'static str {
        self.object_type().type_name()
    }
}

/// 对象引用：身份 + 类型的轻量描述，可直接放进句柄表。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectRef {
    /// 对象 ID。
    pub id: ObjectId,
    /// 对象类型。
    pub ty: ObjectType,
}

impl KernelObject for ObjectRef {
    fn id(&self) -> ObjectId {
        self.id
    }
    fn object_type(&self) -> ObjectType {
        self.ty
    }
}

/// 对象管理器：为新对象分配永不复用的 ID。
pub struct ObjectManager {
    ids: IdAllocator,
}

impl ObjectManager {
    /// 新建。
    pub const fn new() -> Self {
        ObjectManager { ids: IdAllocator::new() }
    }

    /// 登记一个新对象，返回它的引用；ID 用尽时拒绝（不回绕复用旧 ID）。
    pub fn create(&self, ty: ObjectType) -> Result<ObjectRef, IdExhausted> {
        Ok(ObjectRef { id: ObjectId(self.ids.allocate().ok_or(IdExhausted)?), ty })
    }

    /// 迄今创建的对象数。
    pub fn created(&self) -> u64 {
        self.ids.allocated()
    }
}

impl Default for ObjectManager {
    fn default() -> Self {
        Self::new()
    }
}

/// 句柄原始值的唯一事实来源。
///
/// 所有出现句柄值的地方（`HandleId`、IPC 记录、`SpawnDesc` 输出、用户侧数组）都必须引用它，
/// 不允许各写各的整数宽度。位宽是**编译期**决定：它进入系统调用寄存器约定与共享内存布局，
/// 运行时可变会让同一二进制在不同配置下互不兼容。
/// English: single source of truth for the raw handle width (compile-time).
pub type HandleRaw = u64;

/// 句柄低位用于索引的位数。
pub const HANDLE_INDEX_BITS: u32 = 32;
/// 句柄高位用于代次的位数。
pub const HANDLE_GEN_BITS: u32 = 32;

const HANDLE_INDEX_MASK: HandleRaw = (1 << HANDLE_INDEX_BITS) - 1;

/// 一个句柄值在内存与线格式里占用的字节数（由位宽别名推导，调用点不得写死 4 或 8）。
/// Byte width of one handle value on the wire and in memory.
pub const HANDLE_BYTES: usize = core::mem::size_of::<HandleRaw>();

/// 代次可表示的最大值；达到它之后槽位永久退役。
const MAX_GENERATION: u32 = if HANDLE_GEN_BITS >= 32 { u32::MAX } else { (1u32 << HANDLE_GEN_BITS) - 1 };

/// 句柄值（不透明）。用户态只看到 [`HandleId::raw`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HandleId(HandleRaw);

impl HandleId {
    /// 空句柄（永远无效）。
    pub const NULL: HandleId = HandleId(0);

    fn encode(index: usize, generation: u32) -> HandleId {
        HandleId(((generation as HandleRaw) << HANDLE_INDEX_BITS) | (index as HandleRaw + 1))
    }

    fn index(self) -> Option<usize> {
        let low = self.0 & HANDLE_INDEX_MASK;
        usize::try_from(low.checked_sub(1)?).ok()
    }

    fn generation(self) -> u32 {
        (self.0 >> HANDLE_INDEX_BITS) as u32
    }

    /// 原始值（跨陷入边界传递用）。
    pub const fn raw(self) -> HandleRaw {
        self.0
    }

    /// 由原始值还原（不做校验，校验发生在查表时）。
    pub const fn from_raw(raw: HandleRaw) -> HandleId {
        HandleId(raw)
    }
}

/// 句柄操作错误（`system.handle.error.*`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleError {
    /// 句柄不存在、已关闭，或世代不匹配（关闭后复用）。
    Invalid,
    /// 句柄权限不足。
    RightsDenied,
    /// 句柄表已满。
    TableFull,
}

impl HandleError {
    /// 规范错误名。
    pub const fn name(self) -> &'static str {
        match self {
            HandleError::Invalid => "system.handle.error.invalid",
            HandleError::RightsDenied => "system.handle.error.rights_denied",
            HandleError::TableFull => "system.handle.error.table_full",
        }
    }
}

/// 句柄表的一个槽位。
struct Slot<V> {
    /// 当前世代：槽位每被释放一次加一。
    generation: u32,
    /// 世代耗尽后永久退役，不再分配。
    retired: bool,
    /// 占用时的值与权限。
    entry: Option<(V, Rights)>,
}

impl<V> Slot<V> {
    const EMPTY: Slot<V> = Slot { generation: 0, retired: false, entry: None };
}

/// 固定容量（`N` ≤ 65535）的句柄表，不使用堆。
pub struct HandleTable<V, const N: usize> {
    slots: [Slot<V>; N],
    live: usize,
}

impl<V, const N: usize> HandleTable<V, N> {
    /// 新建空表。
    pub const fn new() -> Self {
        assert!(N > 0 && N < 0xFFFF, "句柄表容量必须在 1..65535 之间");
        HandleTable { slots: [const { Slot::EMPTY }; N], live: 0 }
    }

    /// 放入一个值，返回新句柄。优先使用编号最小的空闲槽位。
    pub fn put(&mut self, value: V, rights: Rights) -> Result<HandleId, HandleError> {
        let (index, slot) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, s)| s.entry.is_none() && !s.retired)
            .ok_or(HandleError::TableFull)?;
        slot.entry = Some((value, rights));
        self.live += 1;
        Ok(HandleId::encode(index, slot.generation))
    }

    /// Atomically move one handle between distinct tables at the API boundary.
    /// Author: chatgpt. Caller must serialize both tables; no callback occurs
    /// between destination insertion and source removal. Errors leave both intact.
    pub fn transfer_to<const M: usize>(&mut self, h: HandleId, to: &mut HandleTable<V, M>)
        -> Result<HandleId, HandleError> where V: Copy
    {
        let (value, rights) = self.get(h)?;
        if !rights.contains(Rights::TRANSFER) { return Err(HandleError::RightsDenied); }
        // Destination insertion can fail; do it before touching the source.
        let moved = to.put(*value, rights)?;
        self.remove(h).expect("exclusive validated source handle cannot disappear");
        Ok(moved)
    }

    /// 查找句柄对应的槽位；世代不匹配视为无效。
    fn slot(&self, h: HandleId) -> Result<&Slot<V>, HandleError> {
        let slot = h.index().and_then(|i| self.slots.get(i)).ok_or(HandleError::Invalid)?;
        if slot.entry.is_none() || slot.generation != h.generation() {
            return Err(HandleError::Invalid);
        }
        Ok(slot)
    }

    /// 取值与权限。
    pub fn get(&self, h: HandleId) -> Result<(&V, Rights), HandleError> {
        let (v, r) = self.slot(h)?.entry.as_ref().ok_or(HandleError::Invalid)?;
        Ok((v, *r))
    }

    /// 取值并检查句柄至少拥有 `required` 权限（统一权限检查入口）。
    pub fn get_checked(&self, h: HandleId, required: Rights) -> Result<&V, HandleError> {
        let (v, r) = self.get(h)?;
        if r.contains(required) {
            Ok(v)
        } else {
            Err(HandleError::RightsDenied)
        }
    }

    /// 原地降低句柄权限（`system.handle.restrict` 的实现）：新权限必须是原权限的子集（只减不增），
    /// 否则 [`HandleError::RightsDenied`]。与下方「复制并降权」的 `restrict` 不同，本函数不产生新句柄。
    pub fn reduce_rights(&mut self, h: HandleId, rights: Rights) -> Result<(), HandleError> {
        self.slot(h)?;
        let index = h.index().ok_or(HandleError::Invalid)?;
        let (_, current) = self.slots[index].entry.as_mut().ok_or(HandleError::Invalid)?;
        if !current.contains(rights) {
            return Err(HandleError::RightsDenied);
        }
        *current = rights;
        Ok(())
    }

    /// 还能放入多少个句柄（空闲且未退役的槽位数）。
    pub fn free_slots(&self) -> usize {
        self.slots.iter().filter(|s| s.entry.is_none() && !s.retired).count()
    }

    /// 关闭全部句柄，对每个取回的值调用 `f`（进程退出时关闭整张句柄表用）。返回关闭的数量。
    pub fn close_all(&mut self, mut f: impl FnMut(V)) -> usize {
        let mut n = 0;
        for slot in self.slots.iter_mut() {
            if let Some((value, _)) = slot.entry.take() {
                // 代次达到「可表示的最大值」时退役：位宽是索引+代次之和，
                // 超过这个值再编码就会截断并让旧句柄重新有效。
                if slot.generation >= MAX_GENERATION {
                    slot.retired = true;
                } else {
                    slot.generation += 1;
                }
                self.live -= 1;
                n += 1;
                f(value);
            }
        }
        n
    }

    /// 当前有效句柄数。
    pub fn live_handles(&self) -> usize {
        self.live
    }

    /// 关闭句柄并取回值。之后该句柄值永远无效。
    /// 仅测试使用：把某个槽位的代次直接设为 `gen`（用于验证代次耗尽语义）。
    #[cfg(test)]
    pub fn force_generation_for_test(&mut self, index: usize, gen: u32) {
        if let Some(slot) = self.slots.get_mut(index) {
            slot.generation = gen;
        }
    }

    pub fn remove(&mut self, h: HandleId) -> Result<V, HandleError> {
        self.slot(h)?;
        let index = h.index().ok_or(HandleError::Invalid)?;
        let slot = &mut self.slots[index];
        let (value, _) = slot.entry.take().ok_or(HandleError::Invalid)?;
        if slot.generation >= MAX_GENERATION {
            slot.retired = true;
        } else {
            slot.generation += 1;
        }
        self.live -= 1;
        Ok(value)
    }

    /// 当前存活句柄数。
    pub fn len(&self) -> usize {
        self.live
    }

    /// 是否没有存活句柄。
    pub fn is_empty(&self) -> bool {
        self.live == 0
    }
}

impl<V: Clone, const N: usize> HandleTable<V, N> {
    /// 复制句柄并把权限降为 `self ∩ mask`（`system.handle.restrict`：只能减不能增）。
    pub fn restrict(&mut self, h: HandleId, mask: Rights) -> Result<HandleId, HandleError> {
        let (v, r) = self.get(h)?;
        let (v, r) = (v.clone(), r.intersect(mask));
        self.put(v, r)
    }
}

impl<V, const N: usize> Default for HandleTable<V, N> {
    fn default() -> Self {
        Self::new()
    }
}

/// 带代次的槽位里「代次用尽、永久退役」的标记值。
/// Sentinel generation of a slot that is permanently retired.
pub const GENERATION_RETIRED: u32 = u32::MAX;

/// 槽位释放后的下一个代次：只增不回绕；再增就会撞上 [`GENERATION_RETIRED`] 时返回它，槽位从此退役。
/// 凡是「标识 = 槽位 + 代次」、并且标识会被长期持有的地方（句柄、CPU 组……）都用它推进代次——
/// 回绕会让旧标识在槽位复用后「复活」，指向一个毫不相干的新对象。
/// Next generation for a slot (never wraps; returns [`GENERATION_RETIRED`] when exhausted).
pub const fn advance_generation(g: u32) -> u32 {
    if g >= GENERATION_RETIRED - 1 {
        GENERATION_RETIRED
    } else {
        g + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rights_set_algebra() {
        let wc = Rights::WAIT.union(Rights::CONTROL);
        assert!(wc.contains(Rights::WAIT));
        assert!(!wc.contains(Rights::READ));
        assert_eq!(wc.intersect(Rights::CONTROL), Rights::CONTROL);
        assert_eq!(wc.difference(Rights::WAIT), Rights::CONTROL);
        assert!(Rights::NONE.is_empty());
        assert_eq!(Rights::from_bits_truncate(0xFFFF_FFFF), Rights::ALL);
    }

    #[test]
    fn rights_display() {
        assert_eq!(format!("{}", Rights::WAIT.union(Rights::CONTROL)), "WAIT|CONTROL");
        assert_eq!(format!("{}", Rights::NONE), "NONE");
        assert_eq!(format!("{}", Rights::ALL), "READ|WRITE|EXECUTE|WAIT|CONTROL|DUPLICATE|TRANSFER|MAP", "M4.0 v0.6 的 DUPLICATE / TRANSFER 与 DRV-1C 的 MAP");
    }

    #[test]
    fn id_allocator_is_monotonic_and_starts_at_one() {
        let ids = IdAllocator::new();
        assert_eq!(ids.allocate(), Some(1));
        assert_eq!(ids.allocate(), Some(2));
        assert_eq!(ids.allocated(), 2);
        assert!(!ids.exhausted());
    }

    #[test]
    fn id_allocator_fails_on_exhaustion_without_wrapping() {
        let ids = IdAllocator::starting_at(u64::MAX - 1);
        assert_eq!(ids.allocate(), Some(u64::MAX - 1));
        assert_eq!(ids.allocate(), Some(u64::MAX), "最后一个可用 ID");
        assert_eq!(ids.allocate(), None, "用尽后拒绝");
        assert_eq!(ids.allocate(), None, "用尽状态保持，绝不回绕到 0/1");
        assert!(ids.exhausted());
        assert_eq!(ids.allocated(), u64::MAX);
        let om = ObjectManager { ids: IdAllocator::starting_at(u64::MAX) };
        assert!(om.create(ObjectType::Event).is_ok());
        assert_eq!(om.create(ObjectType::Event), Err(IdExhausted));
    }

    #[test]
    fn id_allocator_is_unique_under_contention() {
        extern crate std;
        use std::sync::Arc;
        use std::vec::Vec;
        // 从接近上限处开始，多线程争抢：发出的 ID 互不相同，且总数恰为剩余量
        let ids = Arc::new(IdAllocator::starting_at(u64::MAX - 999));
        let hs: Vec<_> = (0..4)
            .map(|_| {
                let ids = ids.clone();
                std::thread::spawn(move || {
                    let mut got = Vec::new();
                    while let Some(v) = ids.allocate() {
                        got.push(v);
                    }
                    got
                })
            })
            .collect();
        let mut all: Vec<u64> = hs.into_iter().flat_map(|h| h.join().unwrap()).collect();
        all.sort_unstable();
        let n = all.len();
        all.dedup();
        assert_eq!(n, 1000);
        assert_eq!(all.len(), 1000, "无重复 ID");
        assert_eq!(all[0], u64::MAX - 999);
    }

    #[test]
    fn object_manager_never_reuses_ids() {
        let om = ObjectManager::new();
        let a = om.create(ObjectType::Event).unwrap();
        let b = om.create(ObjectType::Event).unwrap();
        assert_ne!(a.id(), b.id());
        assert_eq!(a.type_name(), "Event");
        assert_eq!(om.created(), 2);
    }

    #[test]
    fn handle_put_get_remove() {
        let mut t: HandleTable<u32, 4> = HandleTable::new();
        let h = t.put(7, Rights::READ).unwrap();
        assert_eq!(h.raw(), 1, "第一个句柄是槽位 0、世代 0 ⇒ 1");
        assert_eq!(t.get(h).unwrap(), (&7, Rights::READ));
        assert_eq!(t.remove(h), Ok(7));
        assert!(t.is_empty());
        assert_eq!(t.get(HandleId::NULL), Err(HandleError::Invalid));
    }

    #[test]
    fn stale_handle_rejected_after_slot_reuse() {
        let mut t: HandleTable<u32, 1> = HandleTable::new();
        let old = t.put(1, Rights::ALL).unwrap();
        t.remove(old).unwrap();
        let new = t.put(2, Rights::ALL).unwrap();
        assert_ne!(old, new, "同一槽位复用后句柄值必须不同");
        assert_eq!(t.get(old), Err(HandleError::Invalid));
        assert_eq!(t.remove(old), Err(HandleError::Invalid), "旧句柄不能关掉新对象");
        assert_eq!(t.get(new).unwrap().0, &2);
    }

    #[test]
    fn table_full_and_rights_check() {
        let mut t: HandleTable<u8, 2> = HandleTable::new();
        let h = t.put(1, Rights::WAIT).unwrap();
        t.put(2, Rights::WAIT).unwrap();
        assert_eq!(t.put(3, Rights::WAIT), Err(HandleError::TableFull));
        assert_eq!(t.get_checked(h, Rights::WAIT), Ok(&1));
        assert_eq!(t.get_checked(h, Rights::CONTROL), Err(HandleError::RightsDenied));
        assert_eq!(HandleError::RightsDenied.name(), "system.handle.error.rights_denied");
    }

    #[test]
    fn restrict_only_reduces_rights() {
        let mut t: HandleTable<u8, 4> = HandleTable::new();
        let h = t.put(9, Rights::WAIT.union(Rights::CONTROL)).unwrap();
        let r = t.restrict(h, Rights::WAIT.union(Rights::WRITE)).unwrap();
        assert_eq!(t.get(r).unwrap().1, Rights::WAIT, "WRITE 不能被凭空加上");
        assert_eq!(t.get_checked(r, Rights::CONTROL), Err(HandleError::RightsDenied));
    }

    #[test]
    fn handle_width_matches_declared_bits() {
        // 「不硬编码」的守卫：索引位 + 代次位必须恰好填满原始值的宽度。
        assert_eq!(
            HANDLE_INDEX_BITS + HANDLE_GEN_BITS,
            (core::mem::size_of::<HandleRaw>() * 8) as u32,
            "句柄位宽常量与 HandleRaw 的实际宽度不一致"
        );
        assert_eq!(HANDLE_BYTES, core::mem::size_of::<HandleRaw>(), "线格式元素宽度必须随句柄宽度推导");
    }

    #[test]
    fn slot_retires_when_generation_exhausted() {
        let mut t: HandleTable<u8, 1> = HandleTable::new();
        // 逐次递增跑不完；直接把槽位摆到「可表示的最大代次」再放进/取出一次。
        let max_gen = MAX_GENERATION;
        t.force_generation_for_test(0, max_gen);
        let h = t.put(0, Rights::NONE).unwrap();
        t.remove(h).unwrap();
        assert_eq!(t.put(0, Rights::NONE), Err(HandleError::TableFull), "世代耗尽的槽位不再复用");
    }

    #[test]
    fn duplicate_transfer_bits_restrict_and_leaf_rule() {
        let all = Rights::ALL;
        assert!(all.contains(Rights::DUPLICATE) && all.contains(Rights::TRANSFER));
        assert_eq!(Rights::from_bits_truncate(0xFFFF), Rights::ALL, "未定义的位被丢弃");
        let r = Rights::WAIT.union(Rights::DUPLICATE);
        assert_eq!(format!("{}", r), "WAIT|DUPLICATE");
        let mut t: HandleTable<u32, 2> = HandleTable::new();
        let h = t.put(1, r).unwrap();
        assert_eq!(t.reduce_rights(h, Rights::WAIT.union(Rights::TRANSFER)), Err(HandleError::RightsDenied), "不能经 restrict 提权");
        t.reduce_rights(h, Rights::WAIT).unwrap();
        assert_eq!(t.get(h).unwrap().1, Rights::WAIT);
        assert_eq!(t.free_slots(), 1);
        assert!(ObjectType::Task.is_transferable_v1() && ObjectType::Event.is_transferable_v1());
        assert!(ObjectType::Device.is_transferable_v1(), "设备对象是叶子：关闭句柄不销毁设备表项");
        assert!(!ObjectType::Channel.is_transferable_v1() && !ObjectType::Process.is_transferable_v1());
        assert!(!ObjectType::Ring.is_transferable_v1() && !ObjectType::AddressSpace.is_transferable_v1());
        assert!(!ObjectType::Interrupt.is_transferable_v1(), "中断绑定归属创建它的进程");
        assert_eq!(ObjectType::Interrupt.type_name(), "Interrupt");
    }

    #[test]
    fn generations_advance_and_retire_instead_of_wrapping() {
        assert_eq!(advance_generation(0), 1);
        assert_eq!(advance_generation(GENERATION_RETIRED - 2), GENERATION_RETIRED - 1);
        assert_eq!(advance_generation(GENERATION_RETIRED - 1), GENERATION_RETIRED, "用尽即退役，不回到 0");
        assert_eq!(advance_generation(GENERATION_RETIRED), GENERATION_RETIRED, "退役后保持退役");
    }
}

#[cfg(kani)]
mod fv1_generation {
    use super::*;
    #[kani::proof]
    #[kani::unwind(3)]
    fn handle_generation_does_not_wrap_or_resurrect() {
        let mut table = HandleTable::<u8, 1>::new();
        // A vacant reusable slot at an arbitrary generation; all other state
        // is constructor-valid. This includes the final non-retired generation.
        let generation: u32 = kani::any();
        table.slots[0].generation = generation;
        let old = table.put(7, Rights::READ).unwrap();
        assert_eq!(table.remove(old), Ok(7));
        assert_eq!(table.get(old), Err(HandleError::Invalid));
        if generation == MAX_GENERATION {
            assert_eq!(table.put(8, Rights::READ), Err(HandleError::TableFull));
        } else {
            let new = table.put(8, Rights::READ).unwrap();
            assert_ne!(old, new);
            assert_eq!(table.get(old), Err(HandleError::Invalid));
        }
    }
}
