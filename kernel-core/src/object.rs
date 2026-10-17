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
use core::sync::atomic::{AtomicU64, Ordering};

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
    /// 全部已定义的权限。
    pub const ALL: Rights = Rights(0b1_1111);

    /// 位名表（按位序），用于格式化输出。
    const NAMES: [(Rights, &'static str); 5] = [
        (Rights::READ, "READ"),
        (Rights::WRITE, "WRITE"),
        (Rights::EXECUTE, "EXECUTE"),
        (Rights::WAIT, "WAIT"),
        (Rights::CONTROL, "CONTROL"),
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
pub struct IdAllocator {
    next: AtomicU64,
}

impl IdAllocator {
    /// 新建，从 1 开始分配。
    pub const fn new() -> Self {
        IdAllocator { next: AtomicU64::new(1) }
    }

    /// 取下一个 ID。
    pub fn allocate(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed)
    }

    /// 已分配的个数。
    pub fn allocated(&self) -> u64 {
        self.next.load(Ordering::Relaxed) - 1
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
    /// IPC 通道（`system.channel` 领域，M3.4 实现）。
    Channel,
    /// 线程/执行流（`system.task` 领域）。
    Task,
}

impl ObjectType {
    /// 类型名（输出与元数据用）。
    pub const fn type_name(self) -> &'static str {
        match self {
            ObjectType::Event => "Event",
            ObjectType::Timer => "Timer",
            ObjectType::Ring => "Ring",
            ObjectType::AddressSpace => "AddressSpace",
            ObjectType::Channel => "Channel",
            ObjectType::Task => "Task",
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

    /// 登记一个新对象，返回它的引用。
    pub fn create(&self, ty: ObjectType) -> ObjectRef {
        ObjectRef { id: ObjectId(self.ids.allocate()), ty }
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

/// 句柄值（不透明）。用户态只看到 [`HandleId::raw`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HandleId(u32);

impl HandleId {
    /// 空句柄（永远无效）。
    pub const NULL: HandleId = HandleId(0);

    fn encode(index: usize, generation: u16) -> HandleId {
        HandleId(((generation as u32) << 16) | (index as u32 + 1))
    }

    fn index(self) -> Option<usize> {
        let low = (self.0 & 0xFFFF) as usize;
        low.checked_sub(1)
    }

    fn generation(self) -> u16 {
        (self.0 >> 16) as u16
    }

    /// 原始值（跨陷入边界传递用）。
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// 由原始值还原（不做校验，校验发生在查表时）。
    pub const fn from_raw(raw: u32) -> HandleId {
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
    generation: u16,
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

    /// 关闭句柄并取回值。之后该句柄值永远无效。
    pub fn remove(&mut self, h: HandleId) -> Result<V, HandleError> {
        self.slot(h)?;
        let index = h.index().ok_or(HandleError::Invalid)?;
        let slot = &mut self.slots[index];
        let (value, _) = slot.entry.take().ok_or(HandleError::Invalid)?;
        match slot.generation.checked_add(1) {
            Some(g) => slot.generation = g,
            None => slot.retired = true,
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
        assert_eq!(format!("{}", Rights::ALL), "READ|WRITE|EXECUTE|WAIT|CONTROL");
    }

    #[test]
    fn id_allocator_is_monotonic_and_starts_at_one() {
        let ids = IdAllocator::new();
        assert_eq!(ids.allocate(), 1);
        assert_eq!(ids.allocate(), 2);
        assert_eq!(ids.allocated(), 2);
    }

    #[test]
    fn object_manager_never_reuses_ids() {
        let om = ObjectManager::new();
        let a = om.create(ObjectType::Event);
        let b = om.create(ObjectType::Event);
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
    fn slot_retires_when_generation_exhausted() {
        let mut t: HandleTable<u8, 1> = HandleTable::new();
        for _ in 0..=u16::MAX as u32 {
            let h = t.put(0, Rights::NONE).unwrap();
            t.remove(h).unwrap();
        }
        assert_eq!(t.put(0, Rights::NONE), Err(HandleError::TableFull), "世代耗尽的槽位不再复用");
    }
}
