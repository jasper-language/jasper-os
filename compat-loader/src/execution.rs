//! Linux ELF 初始化编排、初始栈构造和进程入口交接。
//!
//! Linux ELF initialization ordering, initial-stack construction, and process-entry handoff.
//! This module never executes untrusted ELF bytes itself. It validates a complete entry plan and
//! transfers control only through an explicitly supplied execution backend.

use alloc::vec;
use alloc::vec::Vec;

use super::{plan_lifecycle_order, ImageLayout, LifecycleCallbacks, LoadPlan, LoaderError};

const MAX_MODULES: usize = 256;
const MAX_ENTRY_CALLS: usize = 65_536;
const MAX_STACK_BYTES: u64 = 16 * 1024 * 1024;
const MAX_STACK_ITEMS: usize = 4096;
const MAX_AUXV_ENTRIES: usize = 128;
const MAX_USER_ADDRESS: u64 = 1 << 47;

const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_FLAGS: u64 = 8;
const AT_ENTRY: u64 = 9;
const AT_RANDOM: u64 = 25;
const AT_EXECFN: u64 = 31;

/// 初始栈中的一项 auxv 键值对。
///
/// One auxv key/value pair in the initial process stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuxvEntry {
    /// Linux auxv 类型。/ Linux auxv type.
    pub key: u64,
    /// 与类型对应的值。/ Value associated with the type.
    pub value: u64,
}

/// 一个生命周期入口调用的类别。
///
/// Kind of one lifecycle entry invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryCallKind {
    Init,
    InitArray { index: u32 },
    Fini,
    FiniArray { index: u32 },
}

/// 已完成验证的生命周期入口调用。
///
/// A validated lifecycle entry invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryCall {
    /// 定义回调的模块。/ Module defining the callback.
    pub module_id: u64,
    /// 已验证的回调地址。/ Validated callback address.
    pub address: u64,
    /// ELF 初始化或终结类别。/ ELF initialization or finalization category.
    pub kind: EntryCallKind,
}

/// 参与初始化的一个已装载对象。
///
/// One loaded object participating in dynamic initialization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeModule {
    /// 非零稳定模块标识。/ Non-zero stable module identifier.
    pub module_id: u64,
    /// 已映射对象的运行布局。/ Runtime layout of the mapped object.
    pub image: ImageLayout,
    /// 重定位后读取的生命周期回调。/ Lifecycle callbacks read after relocation.
    pub callbacks: LifecycleCallbacks,
    /// 依赖模块索引，必须先初始化。/ Required module indices that initialize first.
    pub requires: Vec<usize>,
    /// 是否要求未修改 Linux 解释器。/ Whether an unmodified Linux interpreter is required.
    pub interpreter_required: bool,
}

/// 进程实际开始执行的位置。
///
/// Location from which the target process starts executing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntrySource {
    Executable,
    Interpreter,
}

/// 可审计的初始化、终结和程序入口计划。
///
/// Auditable initialization, finalization, and program-entry plan. Dependency order and every
/// callback address are validated before an execution backend receives any call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionPlan {
    init_calls: Vec<EntryCall>,
    fini_calls: Vec<EntryCall>,
    program_entry: u64,
    interpreter_entry: Option<u64>,
    entry: u64,
    entry_source: EntrySource,
}

impl ExecutionPlan {
    /// 返回依赖优先的初始化入口。 / Returns dependency-first initializer calls.
    pub fn init_calls(&self) -> &[EntryCall] {
        &self.init_calls
    }

    /// 返回依赖后终结的入口。 / Returns calls that finalize dependents first.
    pub fn fini_calls(&self) -> &[EntryCall] {
        &self.fini_calls
    }

    /// 返回可执行程序自身的入口地址。 / Returns the executable's own entry address.
    pub const fn program_entry(&self) -> u64 {
        self.program_entry
    }

    /// 返回解释器入口地址（若有）。 / Returns the interpreter entry, when present.
    pub const fn interpreter_entry(&self) -> Option<u64> {
        self.interpreter_entry
    }

    /// 返回后端实际接收的控制流入口。 / Returns the control-flow entry handed to the backend.
    pub const fn entry(&self) -> u64 {
        self.entry
    }

    /// 返回入口属于程序映像还是解释器。 / Returns whether entry belongs to the executable or interpreter.
    pub const fn entry_source(&self) -> EntrySource {
        self.entry_source
    }

    /// 构建单个进程对象图的初始化、终结和入口顺序。
    ///
    /// Builds initialization, finalization, and entry order for one process object graph.
    /// `root` is the executable object. A dynamic executable requires an interpreter image.
    pub fn new(
        modules: &[RuntimeModule],
        root: usize,
        interpreter: Option<&ImageLayout>,
    ) -> Result<Self, LoaderError> {
        if modules.is_empty()
            || modules.len() > MAX_MODULES
            || root >= modules.len()
            || modules[root].module_id == 0
        {
            return Err(LoaderError::BadExecution);
        }
        for (index, module) in modules.iter().enumerate() {
            if module.module_id == 0
                || modules[..index]
                    .iter()
                    .any(|previous| previous.module_id == module.module_id)
            {
                return Err(LoaderError::BadExecution);
            }
        }
        let requires = modules
            .iter()
            .map(|module| module.requires.clone())
            .collect::<Vec<_>>();
        let order = plan_lifecycle_order(&requires)?;
        let mut init_calls = Vec::new();
        for module_index in order.initializers {
            append_initializers(&mut init_calls, &modules[module_index])?;
        }
        let mut fini_calls = Vec::new();
        for module_index in order.finalizers {
            append_finalizers(&mut fini_calls, &modules[module_index])?;
        }
        if init_calls.len() > MAX_ENTRY_CALLS || fini_calls.len() > MAX_ENTRY_CALLS {
            return Err(LoaderError::BadExecution);
        }
        let program_entry = modules[root].image.entry;
        if !executable_entry(&modules[root].image, program_entry) {
            return Err(LoaderError::BadExecution);
        }
        let interpreter_entry = match interpreter {
            Some(image) if modules[root].interpreter_required => {
                if !executable_entry(image, image.entry) {
                    return Err(LoaderError::BadExecution);
                }
                Some(image.entry)
            }
            Some(_) => return Err(LoaderError::BadExecution),
            None if modules[root].interpreter_required => return Err(LoaderError::BadExecution),
            None => None,
        };
        let (entry, entry_source) = interpreter_entry
            .map(|entry| (entry, EntrySource::Interpreter))
            .unwrap_or((program_entry, EntrySource::Executable));
        Ok(Self {
            init_calls,
            fini_calls,
            program_entry,
            interpreter_entry,
            entry,
            entry_source,
        })
    }
}

fn append_initializers(
    output: &mut Vec<EntryCall>,
    module: &RuntimeModule,
) -> Result<(), LoaderError> {
    if let Some(address) = module.callbacks.init {
        append_call(output, module, address, EntryCallKind::Init)?;
    }
    for (index, address) in module.callbacks.init_array.iter().copied().enumerate() {
        append_call(
            output,
            module,
            address,
            EntryCallKind::InitArray {
                index: u32::try_from(index).map_err(|_| LoaderError::BadExecution)?,
            },
        )?;
    }
    Ok(())
}

fn append_finalizers(
    output: &mut Vec<EntryCall>,
    module: &RuntimeModule,
) -> Result<(), LoaderError> {
    let count =
        u32::try_from(module.callbacks.fini_array.len()).map_err(|_| LoaderError::BadExecution)?;
    for (index, address) in module
        .callbacks
        .fini_array
        .iter()
        .rev()
        .copied()
        .enumerate()
    {
        append_call(
            output,
            module,
            address,
            EntryCallKind::FiniArray {
                index: count - 1 - index as u32,
            },
        )?;
    }
    if let Some(address) = module.callbacks.fini {
        append_call(output, module, address, EntryCallKind::Fini)?;
    }
    Ok(())
}

fn append_call(
    output: &mut Vec<EntryCall>,
    module: &RuntimeModule,
    address: u64,
    kind: EntryCallKind,
) -> Result<(), LoaderError> {
    if output.len() == MAX_ENTRY_CALLS || !executable_entry(&module.image, address) {
        return Err(LoaderError::BadExecution);
    }
    output.push(EntryCall {
        module_id: module.module_id,
        address,
        kind,
    });
    Ok(())
}

fn executable_entry(image: &ImageLayout, address: u64) -> bool {
    image.segments.iter().any(|segment| {
        segment.permissions.executable
            && segment
                .end()
                .is_some_and(|end| address >= segment.load_address && address < end)
    })
}

/// 构造 Linux x86_64 `_start` 所需的初始栈数据和指针。
///
/// Inputs required to build the initial Linux x86_64 stack.
#[derive(Clone, Copy, Debug)]
pub struct InitialStackInput<'a> {
    /// 16 字节对齐的栈上界。/ 16-byte-aligned stack upper bound.
    pub stack_top: u64,
    /// 不含 NUL 的参数。/ Arguments without embedded NUL bytes.
    pub argv: &'a [&'a [u8]],
    /// 不含 NUL 的环境变量。/ Environment values without embedded NUL bytes.
    pub envp: &'a [&'a [u8]],
    /// 目标页大小。/ Target page size.
    pub page_size: u64,
    /// 主程序头表运行地址。/ Runtime address of executable program headers.
    pub program_headers: Option<u64>,
    /// 每个程序头条目的字节数。/ Bytes per program-header entry.
    pub program_header_entry_size: u16,
    /// 程序头条目数。/ Program-header entry count.
    pub program_header_count: u16,
    /// 主程序入口，用于 AT_ENTRY。/ Executable entry used for AT_ENTRY.
    pub program_entry: u64,
    /// 解释器 load bias，用于 AT_BASE。/ Interpreter load bias used for AT_BASE.
    pub interpreter_base: u64,
    /// 调用方补充的 auxv。/ Caller-provided auxv entries.
    pub auxv: &'a [AuxvEntry],
    /// 可选 AT_RANDOM 数据。/ Optional AT_RANDOM data.
    pub random: Option<&'a [u8; 16]>,
}

/// 可由真实栈映射后端写入的初始栈计划。
///
/// Initial-stack plan that a real stack-mapping backend can write. `bytes` starts at
/// `stack_pointer` and ends at `stack_top`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialStackPlan {
    stack_pointer: u64,
    stack_top: u64,
    argc: u64,
    argv_pointer: u64,
    envp_pointer: u64,
    auxv_pointer: u64,
    random_pointer: Option<u64>,
    bytes: Vec<u8>,
}

impl InitialStackPlan {
    /// 返回初始栈最低地址；该地址按 16 字节对齐并指向 argc。
    ///
    /// Returns the lowest stack address, aligned to 16 bytes and pointing at argc.
    pub const fn stack_pointer(&self) -> u64 {
        self.stack_pointer
    }

    /// 返回初始栈上界（不含）。 / Returns the exclusive stack upper bound.
    pub const fn stack_top(&self) -> u64 {
        self.stack_top
    }

    /// 返回参数数量。 / Returns the argument count.
    pub const fn argc(&self) -> u64 {
        self.argc
    }

    /// 返回 argv[0] 所在地址。 / Returns the address of argv[0].
    pub const fn argv_pointer(&self) -> u64 {
        self.argv_pointer
    }

    /// 返回环境变量指针数组首地址。 / Returns the first envp pointer.
    pub const fn envp_pointer(&self) -> u64 {
        self.envp_pointer
    }

    /// 返回 auxv 首地址。 / Returns the auxiliary-vector start.
    pub const fn auxv_pointer(&self) -> u64 {
        self.auxv_pointer
    }

    /// 返回 AT_RANDOM 的 16 字节区域。 / Returns the AT_RANDOM byte range.
    pub const fn random_pointer(&self) -> Option<u64> {
        self.random_pointer
    }

    /// 返回从 stack_pointer 到 stack_top 的只读字节。
    ///
    /// Returns the immutable bytes from stack_pointer through stack_top.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// 判断绝对地址范围是否完全位于本栈计划内。
    ///
    /// Returns whether an absolute range lies completely inside this stack plan.
    pub fn contains(&self, address: u64, bytes: u64) -> bool {
        address >= self.stack_pointer
            && address
                .checked_add(bytes)
                .is_some_and(|end| end <= self.stack_top)
    }
}

/// 构造已完成边界和格式校验的初始栈。
///
/// Builds a bounded initial stack containing argc/argv, envp, auxiliary vector, strings and
/// optional random bytes. Every emitted pointer is canonical and lies inside the returned range.
pub fn build_initial_stack(input: InitialStackInput<'_>) -> Result<InitialStackPlan, LoaderError> {
    if input.stack_top == 0
        || input.stack_top >= MAX_USER_ADDRESS
        || !input.stack_top.is_multiple_of(16)
        || input.page_size == 0
        || !input.page_size.is_power_of_two()
        || !valid_user_address(input.program_entry)
        || (input.interpreter_base != 0
            && (!valid_user_address(input.interpreter_base)
                || !input.interpreter_base.is_multiple_of(input.page_size)))
        || input.argv.len() > MAX_STACK_ITEMS
        || input.envp.len() > MAX_STACK_ITEMS
        || input.auxv.len() > MAX_AUXV_ENTRIES
    {
        return Err(LoaderError::BadStack);
    }
    for value in input.argv.iter().chain(input.envp.iter()) {
        if value.contains(&0) {
            return Err(LoaderError::BadStack);
        }
    }
    for pair in input.auxv {
        if pair.key == AT_NULL || reserved_auxv(pair.key) {
            return Err(LoaderError::BadStack);
        }
    }

    let mut high = Vec::<u8>::new();
    let mut argv_offsets = Vec::with_capacity(input.argv.len());
    let mut envp_offsets = Vec::with_capacity(input.envp.len());
    for value in input.argv {
        argv_offsets.push(high.len());
        high.extend_from_slice(value);
        high.push(0);
    }
    for value in input.envp {
        envp_offsets.push(high.len());
        high.extend_from_slice(value);
        high.push(0);
    }
    let random_offset = input.random.map(|random| {
        let offset = high.len();
        high.extend_from_slice(random);
        offset
    });
    if high.len() as u64 > MAX_STACK_BYTES {
        return Err(LoaderError::BadStack);
    }

    let mut auxv = Vec::with_capacity(input.auxv.len() + 9);
    if let Some(program_headers) = input.program_headers {
        let bytes = u64::from(input.program_header_entry_size)
            .checked_mul(u64::from(input.program_header_count))
            .ok_or(LoaderError::BadStack)?;
        if input.program_header_entry_size == 0
            || input.program_header_count == 0
            || !valid_user_address(program_headers)
            || program_headers
                .checked_add(bytes)
                .is_none_or(|end| end > MAX_USER_ADDRESS)
        {
            return Err(LoaderError::BadStack);
        }
        auxv.push(AuxvEntry {
            key: AT_PHDR,
            value: program_headers,
        });
        auxv.push(AuxvEntry {
            key: AT_PHENT,
            value: u64::from(input.program_header_entry_size),
        });
        auxv.push(AuxvEntry {
            key: AT_PHNUM,
            value: u64::from(input.program_header_count),
        });
    } else if input.program_header_entry_size != 0 || input.program_header_count != 0 {
        return Err(LoaderError::BadStack);
    }
    auxv.extend_from_slice(&[
        AuxvEntry {
            key: AT_PAGESZ,
            value: input.page_size,
        },
        AuxvEntry {
            key: AT_BASE,
            value: input.interpreter_base,
        },
        AuxvEntry {
            key: AT_FLAGS,
            value: 0,
        },
        AuxvEntry {
            key: AT_ENTRY,
            value: input.program_entry,
        },
    ]);
    if input.random.is_some() {
        auxv.push(AuxvEntry {
            key: AT_RANDOM,
            value: 0,
        });
    }
    if !input.argv.is_empty() {
        auxv.push(AuxvEntry {
            key: AT_EXECFN,
            value: 0,
        });
    }
    auxv.extend_from_slice(input.auxv);

    let high_start = align_down(
        input
            .stack_top
            .checked_sub(high.len() as u64)
            .ok_or(LoaderError::BadStack)?,
        8,
    );
    let pointer_count = 1usize
        .checked_add(input.argv.len())
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(input.envp.len()))
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(auxv.len().checked_add(1)?.checked_mul(2)?))
        .ok_or(LoaderError::BadStack)?;
    let table_bytes = (pointer_count as u64)
        .checked_mul(8)
        .ok_or(LoaderError::BadStack)?;
    let stack_pointer = align_down(
        high_start
            .checked_sub(table_bytes)
            .ok_or(LoaderError::BadStack)?,
        16,
    );
    let total = input
        .stack_top
        .checked_sub(stack_pointer)
        .ok_or(LoaderError::BadStack)?;
    if total == 0 || total > MAX_STACK_BYTES {
        return Err(LoaderError::BadStack);
    }
    let mut bytes = vec![0u8; usize::try_from(total).map_err(|_| LoaderError::BadStack)?];
    let high_destination =
        usize::try_from(high_start - stack_pointer).map_err(|_| LoaderError::BadStack)?;
    bytes[high_destination..high_destination + high.len()].copy_from_slice(&high);

    let mut cursor = 0usize;
    write_u64(&mut bytes, &mut cursor, input.argv.len() as u64)?;
    let argv_pointer = stack_pointer + cursor as u64;
    for &offset in &argv_offsets {
        write_u64(&mut bytes, &mut cursor, high_start + offset as u64)?;
    }
    write_u64(&mut bytes, &mut cursor, 0)?;
    let envp_pointer = stack_pointer + cursor as u64;
    for offset in envp_offsets {
        write_u64(&mut bytes, &mut cursor, high_start + offset as u64)?;
    }
    write_u64(&mut bytes, &mut cursor, 0)?;
    let auxv_pointer = stack_pointer + cursor as u64;
    let random_pointer = random_offset.map(|offset| high_start + offset as u64);
    let execfn_pointer = argv_offsets
        .first()
        .map(|offset| high_start + *offset as u64);
    for pair in &auxv {
        let value = match pair.key {
            AT_RANDOM => random_pointer.ok_or(LoaderError::BadStack)?,
            AT_EXECFN => execfn_pointer.ok_or(LoaderError::BadStack)?,
            _ => pair.value,
        };
        write_u64(&mut bytes, &mut cursor, pair.key)?;
        write_u64(&mut bytes, &mut cursor, value)?;
    }
    write_u64(&mut bytes, &mut cursor, AT_NULL)?;
    write_u64(&mut bytes, &mut cursor, 0)?;

    Ok(InitialStackPlan {
        stack_pointer,
        stack_top: input.stack_top,
        argc: input.argv.len() as u64,
        argv_pointer,
        envp_pointer,
        auxv_pointer,
        random_pointer,
        bytes,
    })
}

fn reserved_auxv(key: u64) -> bool {
    matches!(
        key,
        AT_PHDR
            | AT_PHENT
            | AT_PHNUM
            | AT_PAGESZ
            | AT_BASE
            | AT_FLAGS
            | AT_ENTRY
            | AT_RANDOM
            | AT_EXECFN
    )
}

fn write_u64(bytes: &mut [u8], cursor: &mut usize, value: u64) -> Result<(), LoaderError> {
    let end = cursor.checked_add(8).ok_or(LoaderError::BadStack)?;
    let destination = bytes.get_mut(*cursor..end).ok_or(LoaderError::BadStack)?;
    destination.copy_from_slice(&value.to_le_bytes());
    *cursor = end;
    Ok(())
}

fn align_down(value: u64, alignment: u64) -> u64 {
    value & !(alignment - 1)
}

fn valid_user_address(address: u64) -> bool {
    address != 0 && address < MAX_USER_ADDRESS
}

/// 准备转交给真实用户态后端的完整入口帧。
///
/// Complete entry frame ready for transfer to a real user-mode backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryFrame {
    /// 后端开始执行的指令地址。/ Instruction address at which the backend starts.
    pub pc: u64,
    /// 入口属于主程序还是解释器。/ Whether entry belongs to the executable or interpreter.
    pub source: EntrySource,
    /// 尚待后端写入和映射的初始栈。/ Initial stack awaiting backend mapping.
    pub stack: InitialStackPlan,
}

/// 真实执行后端必须实现的边界。
///
/// Boundary a real execution backend implements. Calling target code, switching privilege,
/// installing page tables and entering Ring 3 remain backend responsibilities.
pub trait ExecutionBackend {
    /// 调用一个已验证的生命周期入口。
    ///
    /// Invokes one validated lifecycle callback.
    fn call_entry(&mut self, call: EntryCall) -> Result<(), LoaderError>;

    /// 安装页表、特权级和寄存器后交接入口帧。
    ///
    /// Transfers an entry frame after page tables, privilege state, and registers are installed.
    fn transfer(&mut self, frame: EntryFrame) -> Result<(), LoaderError>;
}

/// 直接交接程序或解释器入口，不提前执行目标对象的构造器。
///
/// Transfers the executable or interpreter entry without invoking target constructors. A dynamic
/// executable therefore enters the unmodified interpreter, which owns relocation-ordered
/// initialization. Static/preloaded callers that explicitly own lifecycle execution must use
/// [`run_preloaded_entry`] instead.
pub fn run_process_entry<B: ExecutionBackend>(
    backend: &mut B,
    plan: &ExecutionPlan,
    stack: InitialStackPlan,
) -> Result<(), LoaderError> {
    validate_entry_stack(&stack)?;
    backend.transfer(EntryFrame {
        pc: plan.entry,
        source: plan.entry_source,
        stack,
    })
}

/// 仅供明确承担生命周期调用的预装载镜像使用。
///
/// For preloaded images whose owner explicitly executes ELF lifecycle callbacks. This function
/// must not be used to start an unmodified dynamic Linux program; the interpreter/libc startup
/// path owns those constructor and destructor calls.
pub fn run_preloaded_entry<B: ExecutionBackend>(
    backend: &mut B,
    plan: &ExecutionPlan,
    stack: InitialStackPlan,
) -> Result<(), LoaderError> {
    if plan.entry_source != EntrySource::Executable {
        return Err(LoaderError::BadExecution);
    }
    validate_entry_stack(&stack)?;
    for call in &plan.init_calls {
        backend.call_entry(*call)?;
    }
    backend.transfer(EntryFrame {
        pc: plan.entry,
        source: plan.entry_source,
        stack,
    })
}

fn validate_entry_stack(stack: &InitialStackPlan) -> Result<(), LoaderError> {
    if stack.stack_pointer == 0
        || stack.stack_pointer >= MAX_USER_ADDRESS
        || stack.stack_top == 0
        || stack.stack_top >= MAX_USER_ADDRESS
        || stack.stack_top
            != stack
                .stack_pointer
                .checked_add(stack.bytes.len() as u64)
                .ok_or(LoaderError::BadStack)?
        || !stack.stack_pointer.is_multiple_of(16)
    {
        return Err(LoaderError::BadStack);
    }
    Ok(())
}

/// 按依赖逆序调用进程终结入口。
///
/// Invokes lifecycle finalizers in dependency-reversed order for a preloaded image whose owner
/// explicitly manages teardown. It performs no syscall or privilege transition.
pub fn run_preloaded_exit<B: ExecutionBackend>(
    backend: &mut B,
    plan: &ExecutionPlan,
) -> Result<(), LoaderError> {
    if plan.entry_source != EntrySource::Executable {
        return Err(LoaderError::BadExecution);
    }
    for call in &plan.fini_calls {
        backend.call_entry(*call)?;
    }
    Ok(())
}

/// 从已解析对象生成初始栈所需的程序元数据输入。
///
/// Inputs required to derive initial-stack metadata from one parsed executable.
#[derive(Clone, Copy, Debug)]
pub struct ProgramStackInput<'a> {
    /// 已解析的主程序。/ Parsed executable.
    pub plan: &'a LoadPlan,
    /// 主程序运行布局。/ Executable runtime layout.
    pub image: &'a ImageLayout,
    /// 解释器 load bias。/ Interpreter load bias.
    pub interpreter_base: u64,
    /// 栈上界。/ Stack upper bound.
    pub stack_top: u64,
    /// 参数。/ Arguments.
    pub argv: &'a [&'a [u8]],
    /// 环境变量。/ Environment values.
    pub envp: &'a [&'a [u8]],
    /// 调用方 auxv。/ Caller-provided auxv entries.
    pub auxv: &'a [AuxvEntry],
    /// 可选 AT_RANDOM 数据。/ Optional AT_RANDOM data.
    pub random: Option<&'a [u8; 16]>,
}

/// 从已解析对象生成初始栈所需的程序元数据。
///
/// Builds initial-stack input for one parsed executable and its concrete image layout.
pub fn stack_input_for_program<'a>(
    input: ProgramStackInput<'a>,
) -> Result<InitialStackInput<'a>, LoaderError> {
    let program_headers = match input.plan.program_headers {
        Some(range) => Some(
            input
                .image
                .load_bias
                .checked_add(range.address)
                .ok_or(LoaderError::BadStack)?,
        ),
        None if input.plan.program_header_count == 0 => None,
        None => return Err(LoaderError::BadStack),
    };
    let interpreter_base = match (input.plan.interpreter.is_some(), input.interpreter_base) {
        (true, 0) | (false, 1..) => return Err(LoaderError::BadStack),
        (_, base) => base,
    };
    Ok(InitialStackInput {
        stack_top: input.stack_top,
        argv: input.argv,
        envp: input.envp,
        page_size: input.image.page_size,
        program_headers,
        program_header_entry_size: input.plan.program_header_entry_size,
        program_header_count: input.plan.program_header_count,
        program_entry: input.image.entry,
        interpreter_base,
        auxv: input.auxv,
        random: input.random,
    })
}

/// 已完成边界校验的主程序与未修改解释器布局。
///
/// Validated layouts for one dynamic executable and its unmodified Linux interpreter.
/// The compatibility shim maps both images and transfers control to the interpreter; the
/// interpreter owns dependency loading, runtime relocation, TLS and constructors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DynamicProgramPlan {
    /// 可执行主程序布局。/ Layout of the executable.
    pub executable: ImageLayout,
    /// 解释器布局。/ Layout of the program interpreter.
    pub interpreter: ImageLayout,
    /// 只含解释器入口的受控执行计划。
    ///
    /// Controlled execution plan whose only direct entry is the interpreter.
    pub execution: ExecutionPlan,
}

/// 为主程序和解释器选择互不重叠的真实运行布局。
///
/// Builds disjoint runtime layouts for a dynamic executable and the interpreter named by its
/// `PT_INTERP`. No relocation is applied and no lifecycle callback is invoked here.
/// The caller must map both images, build the auxiliary vector with the main program's
/// `AT_PHDR`/`AT_ENTRY` and the interpreter's `AT_BASE`, then transfer to `execution.entry()`.
pub fn plan_dynamic_program(
    executable_plan: &LoadPlan,
    interpreter_plan: &LoadPlan,
    executable_base: u64,
    interpreter_base: u64,
    page_size: u64,
) -> Result<DynamicProgramPlan, LoaderError> {
    if executable_plan.interpreter.is_none()
        || !executable_plan.position_independent
        || !interpreter_plan.position_independent
        || interpreter_plan.interpreter.is_some()
    {
        return Err(LoaderError::BadInterpreter);
    }
    let executable_bias = super::select_load_bias(executable_plan, executable_base, page_size)?;
    let interpreter_bias = super::select_load_bias(interpreter_plan, interpreter_base, page_size)?;
    let executable = ImageLayout::new(executable_plan, executable_bias, page_size)?;
    let interpreter = ImageLayout::new(interpreter_plan, interpreter_bias, page_size)?;
    if executable.overlaps(&interpreter) {
        return Err(LoaderError::OverlappingImages);
    }
    let modules = [RuntimeModule {
        module_id: 1,
        image: executable.clone(),
        callbacks: LifecycleCallbacks::default(),
        requires: Vec::new(),
        interpreter_required: true,
    }];
    let execution = ExecutionPlan::new(&modules, 0, Some(&interpreter))?;
    if execution.entry_source() != EntrySource::Interpreter
        || execution.entry() != interpreter.entry
        || execution.program_entry() != executable.entry
        || !execution.init_calls().is_empty()
        || !execution.fini_calls().is_empty()
    {
        return Err(LoaderError::BadExecution);
    }
    Ok(DynamicProgramPlan {
        executable,
        interpreter,
        execution,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LifecyclePlan, LoadSegment, TlsSegment, VirtualRange};
    use std::fs;

    fn image_with_entry(base: u64, entry: u64) -> ImageLayout {
        let plan = LoadPlan {
            entry,
            position_independent: false,
            interpreter: None,
            needed: Vec::new(),
            rpaths: Vec::new(),
            runpaths: Vec::new(),
            segments: vec![LoadSegment {
                file_offset: 0,
                virtual_address: base,
                file_bytes: 0x1000,
                memory_bytes: 0x1000,
                align: 0x1000,
                readable: true,
                writable: false,
                executable: true,
            }],
            program_headers: None,
            program_header_entry_size: 0,
            program_header_count: 0,
            tls: None::<TlsSegment>,
            relro: None::<VirtualRange>,
            lifecycle: LifecyclePlan::default(),
            relocations: Vec::new(),
            max_align: 0x1000,
        };
        ImageLayout::new(&plan, 0, 0x1000).unwrap()
    }

    fn module(
        id: u64,
        base: u64,
        requires: Vec<usize>,
        callbacks: LifecycleCallbacks,
    ) -> RuntimeModule {
        RuntimeModule {
            module_id: id,
            image: image_with_entry(base, base + 0x100),
            callbacks,
            requires,
            interpreter_required: false,
        }
    }

    #[derive(Default)]
    struct RecordingBackend {
        calls: Vec<EntryCall>,
        frame: Option<EntryFrame>,
        fail_init: bool,
    }

    impl ExecutionBackend for RecordingBackend {
        fn call_entry(&mut self, call: EntryCall) -> Result<(), LoaderError> {
            self.calls.push(call);
            if self.fail_init {
                return Err(LoaderError::BadExecution);
            }
            Ok(())
        }

        fn transfer(&mut self, frame: EntryFrame) -> Result<(), LoaderError> {
            self.frame = Some(frame);
            Ok(())
        }
    }

    fn stack_for_test() -> InitialStackPlan {
        let arg = b"program".as_slice();
        let env = b"LANG=C".as_slice();
        let argv = [arg];
        let envp = [env];
        build_initial_stack(InitialStackInput {
            stack_top: 0x7fff_0000_0000,
            argv: &argv,
            envp: &envp,
            page_size: 4096,
            program_headers: Some(0x400040),
            program_header_entry_size: 56,
            program_header_count: 12,
            program_entry: 0x401000,
            interpreter_base: 0,
            auxv: &[],
            random: None,
        })
        .unwrap()
    }

    #[test]
    fn dependency_order_and_callback_order_are_fully_validated() {
        let modules = vec![
            module(
                1,
                0x10_0000,
                vec![1],
                LifecycleCallbacks {
                    init: Some(0x10_0100),
                    fini: Some(0x10_0200),
                    init_array: vec![0x10_0300, 0x10_0400],
                    fini_array: vec![0x10_0500, 0x10_0600],
                },
            ),
            module(
                2,
                0x20_0000,
                vec![],
                LifecycleCallbacks {
                    init_array: vec![0x20_0100],
                    ..LifecycleCallbacks::default()
                },
            ),
            module(3, 0x30_0000, vec![1], LifecycleCallbacks::default()),
        ];
        let plan = ExecutionPlan::new(&modules, 0, None).unwrap();
        assert_eq!(
            plan.init_calls
                .iter()
                .map(|call| (call.module_id, call.address, call.kind))
                .collect::<Vec<_>>(),
            vec![
                (2, 0x20_0100, EntryCallKind::InitArray { index: 0 }),
                (1, 0x10_0100, EntryCallKind::Init),
                (1, 0x10_0300, EntryCallKind::InitArray { index: 0 }),
                (1, 0x10_0400, EntryCallKind::InitArray { index: 1 }),
            ]
        );
        assert_eq!(
            plan.fini_calls
                .iter()
                .map(|call| (call.module_id, call.address, call.kind))
                .collect::<Vec<_>>(),
            vec![
                (1, 0x10_0600, EntryCallKind::FiniArray { index: 1 }),
                (1, 0x10_0500, EntryCallKind::FiniArray { index: 0 }),
                (1, 0x10_0200, EntryCallKind::Fini),
            ]
        );
    }

    #[test]
    fn invalid_graph_and_callback_fail_before_backend_transfer() {
        let cyclic = vec![
            module(1, 0x10_0000, vec![1], LifecycleCallbacks::default()),
            module(2, 0x20_0000, vec![0], LifecycleCallbacks::default()),
        ];
        assert_eq!(
            ExecutionPlan::new(&cyclic, 0, None),
            Err(LoaderError::CyclicDependencies)
        );
        let invalid_callback = vec![module(
            1,
            0x10_0000,
            Vec::new(),
            LifecycleCallbacks {
                init: Some(0x90_0000),
                ..LifecycleCallbacks::default()
            },
        )];
        assert_eq!(
            ExecutionPlan::new(&invalid_callback, 0, None),
            Err(LoaderError::BadExecution)
        );
    }

    #[test]
    fn initializer_failure_prevents_process_entry_transfer() {
        let modules = vec![module(
            1,
            0x10_0000,
            Vec::new(),
            LifecycleCallbacks {
                init: Some(0x10_0100),
                ..LifecycleCallbacks::default()
            },
        )];
        let plan = ExecutionPlan::new(&modules, 0, None).unwrap();
        let mut backend = RecordingBackend {
            fail_init: true,
            ..RecordingBackend::default()
        };
        assert_eq!(
            run_preloaded_entry(&mut backend, &plan, stack_for_test()),
            Err(LoaderError::BadExecution)
        );
        assert_eq!(backend.calls.len(), 1);
        assert!(backend.frame.is_none());
    }

    #[test]
    fn process_entry_transfer_never_invokes_target_initializers() {
        let modules = vec![module(
            1,
            0x10_0000,
            Vec::new(),
            LifecycleCallbacks {
                init: Some(0x10_0100),
                init_array: vec![0x10_0300],
                ..LifecycleCallbacks::default()
            },
        )];
        let plan = ExecutionPlan::new(&modules, 0, None).unwrap();
        let mut backend = RecordingBackend::default();
        run_process_entry(&mut backend, &plan, stack_for_test()).unwrap();
        assert!(backend.calls.is_empty());
        assert!(backend.frame.is_some());
    }

    #[test]
    fn finalizers_reach_backend_in_reverse_dependency_order() {
        let modules = vec![
            module(
                1,
                0x10_0000,
                vec![1],
                LifecycleCallbacks {
                    fini: Some(0x10_0200),
                    fini_array: vec![0x10_0500, 0x10_0600],
                    ..LifecycleCallbacks::default()
                },
            ),
            module(
                2,
                0x20_0000,
                Vec::new(),
                LifecycleCallbacks {
                    fini_array: vec![0x20_0100],
                    ..LifecycleCallbacks::default()
                },
            ),
        ];
        let plan = ExecutionPlan::new(&modules, 0, None).unwrap();
        let mut backend = RecordingBackend::default();
        run_preloaded_exit(&mut backend, &plan).unwrap();
        assert_eq!(
            backend
                .calls
                .iter()
                .map(|call| (call.module_id, call.address))
                .collect::<Vec<_>>(),
            vec![
                (1, 0x10_0600),
                (1, 0x10_0500),
                (1, 0x10_0200),
                (2, 0x20_0100),
            ]
        );
    }

    #[test]
    fn initial_stack_has_aligned_vectors_strings_and_auxv() {
        let random = [0x5au8; 16];
        let arg0 = b"/bin/true".as_slice();
        let arg1 = b"argument".as_slice();
        let env = b"PATH=/usr/bin".as_slice();
        let argv = [arg0, arg1];
        let envp = [env];
        let stack = build_initial_stack(InitialStackInput {
            stack_top: 0x7fff_0000_0000,
            argv: &argv,
            envp: &envp,
            page_size: 4096,
            program_headers: Some(0x400040),
            program_header_entry_size: 56,
            program_header_count: 12,
            program_entry: 0x401000,
            interpreter_base: 0x7000_0000_0000,
            auxv: &[AuxvEntry {
                key: 16,
                value: 0x1234,
            }],
            random: Some(&random),
        })
        .unwrap();
        assert_eq!(stack.stack_pointer % 16, 0);
        assert_eq!(
            stack.stack_top - stack.stack_pointer,
            stack.bytes().len() as u64
        );
        assert!(stack.contains(stack.stack_pointer, stack.bytes().len() as u64));
        assert!(!stack.contains(stack.stack_top, 1));
        assert_eq!(read_u64(&stack, stack.stack_pointer), 2);
        assert_eq!(
            string_at(&stack, read_u64(&stack, stack.argv_pointer)),
            arg0
        );
        assert_eq!(
            string_at(&stack, read_u64(&stack, stack.argv_pointer + 8)),
            arg1
        );
        assert_eq!(read_u64(&stack, stack.argv_pointer + 16), 0);
        assert_eq!(string_at(&stack, read_u64(&stack, stack.envp_pointer)), env);
        assert_eq!(read_u64(&stack, stack.envp_pointer + 8), 0);
        assert_eq!(stack.random_pointer, Some(read_aux(&stack, AT_RANDOM)));
        assert_eq!(read_aux(&stack, AT_ENTRY), 0x401000);
        assert_eq!(read_aux(&stack, AT_BASE), 0x7000_0000_0000);
        assert_eq!(string_at(&stack, read_aux(&stack, AT_EXECFN)), b"/bin/true");
        assert_eq!(read_aux(&stack, AT_NULL), 0);
    }

    #[test]
    fn malformed_stack_inputs_fail_closed() {
        let embedded_nul = [b'a', 0, b'b'];
        let argv = [embedded_nul.as_slice()];
        assert_eq!(
            build_initial_stack(InitialStackInput {
                stack_top: 0x7fff_0000_0000,
                argv: &argv,
                envp: &[],
                page_size: 4096,
                program_headers: None,
                program_header_entry_size: 0,
                program_header_count: 0,
                program_entry: 0x401000,
                interpreter_base: 0,
                auxv: &[],
                random: None,
            }),
            Err(LoaderError::BadStack)
        );
        assert_eq!(
            build_initial_stack(InitialStackInput {
                stack_top: 1 << 48,
                argv: &[],
                envp: &[],
                page_size: 4096,
                program_headers: None,
                program_header_entry_size: 0,
                program_header_count: 0,
                program_entry: 0x401000,
                interpreter_base: 0,
                auxv: &[],
                random: None,
            }),
            Err(LoaderError::BadStack)
        );
        assert_eq!(
            build_initial_stack(InitialStackInput {
                stack_top: MAX_USER_ADDRESS,
                argv: &[],
                envp: &[],
                page_size: 4096,
                program_headers: None,
                program_header_entry_size: 0,
                program_header_count: 0,
                program_entry: 0x401000,
                interpreter_base: 0,
                auxv: &[],
                random: None,
            }),
            Err(LoaderError::BadStack)
        );
        assert_eq!(
            build_initial_stack(InitialStackInput {
                stack_top: 0x7fff_0000_0000,
                argv: &[],
                envp: &[],
                page_size: 4096,
                program_headers: Some(0x400040),
                program_header_entry_size: 56,
                program_header_count: 2,
                program_entry: MAX_USER_ADDRESS,
                interpreter_base: 0x7000_0000_0000,
                auxv: &[],
                random: None,
            }),
            Err(LoaderError::BadStack)
        );
        assert_eq!(
            build_initial_stack(InitialStackInput {
                stack_top: 0x7fff_0000_0000,
                argv: &[],
                envp: &[],
                page_size: 4096,
                program_headers: Some(0x400040),
                program_header_entry_size: 56,
                program_header_count: 2,
                program_entry: 0x401000,
                interpreter_base: 0x7000_0000_0008,
                auxv: &[],
                random: None,
            }),
            Err(LoaderError::BadStack)
        );
        assert_eq!(
            build_initial_stack(InitialStackInput {
                stack_top: 0x7fff_0000_0000,
                argv: &[],
                envp: &[],
                page_size: 4096,
                program_headers: None,
                program_header_entry_size: 56,
                program_header_count: 2,
                program_entry: 0x401000,
                interpreter_base: 0,
                auxv: &[],
                random: None,
            }),
            Err(LoaderError::BadStack)
        );
    }

    #[test]
    fn interpreter_base_must_match_the_program_interpreter() {
        let main_bytes = fs::read("/bin/true").unwrap();
        let main_plan = crate::parse(&main_bytes).unwrap();
        let main_image = ImageLayout::new(&main_plan, 0x400000, 4096).unwrap();
        let arg0 = b"/bin/true".as_slice();
        let argv = [arg0];
        assert_eq!(
            stack_input_for_program(ProgramStackInput {
                plan: &main_plan,
                image: &main_image,
                interpreter_base: 0,
                stack_top: 0x7fff_0000_0000,
                argv: &argv,
                envp: &[],
                auxv: &[],
                random: None,
            })
            .unwrap_err(),
            LoaderError::BadStack
        );

        let static_bytes = fs::read("/bin/true").unwrap();
        let mut static_plan = crate::parse(&static_bytes).unwrap();
        static_plan.interpreter = None;
        assert_eq!(
            stack_input_for_program(ProgramStackInput {
                plan: &static_plan,
                image: &main_image,
                interpreter_base: 0x7000_0000_0000,
                stack_top: 0x7fff_0000_0000,
                argv: &argv,
                envp: &[],
                auxv: &[],
                random: None,
            })
            .unwrap_err(),
            LoaderError::BadStack
        );
    }

    #[test]
    fn real_dynamic_true_and_ld_linux_form_disjoint_interpreter_plan() {
        let executable_bytes = fs::read("/usr/bin/true").unwrap();
        let executable_plan = crate::parse(&executable_bytes).unwrap();
        let interpreter_bytes = fs::read("/lib64/ld-linux-x86-64.so.2").unwrap();
        let interpreter_plan = crate::parse(&interpreter_bytes).unwrap();
        let plan = plan_dynamic_program(
            &executable_plan,
            &interpreter_plan,
            0x1000_0040_0000,
            0x1000_2000_0000,
            4096,
        )
        .unwrap();
        assert!(!plan.executable.overlaps(&plan.interpreter));
        assert_eq!(plan.execution.entry(), plan.interpreter.entry);
        assert_eq!(plan.execution.program_entry(), plan.executable.entry);
        assert_eq!(plan.execution.entry_source(), EntrySource::Interpreter);
        assert!(plan.execution.init_calls().is_empty());
        assert!(plan.execution.fini_calls().is_empty());
        assert_eq!(
            plan.executable.load_bias,
            super::super::select_load_bias(&executable_plan, 0x1000_0040_0000, 4096).unwrap()
        );
        assert_eq!(
            plan.interpreter.load_bias,
            super::super::select_load_bias(&interpreter_plan, 0x1000_2000_0000, 4096).unwrap()
        );
    }

    #[test]
    fn dynamic_program_plan_fails_closed_for_static_overlap_and_interpreter_chain() {
        let executable_bytes = fs::read("/usr/bin/true").unwrap();
        let mut executable_plan = crate::parse(&executable_bytes).unwrap();
        let interpreter_bytes = fs::read("/lib64/ld-linux-x86-64.so.2").unwrap();
        let interpreter_plan = crate::parse(&interpreter_bytes).unwrap();

        assert_eq!(
            plan_dynamic_program(
                &executable_plan,
                &interpreter_plan,
                0x1000_0040_0000,
                0x1000_0040_0000,
                4096,
            ),
            Err(LoaderError::OverlappingImages)
        );

        let static_plan = crate::parse(&executable_bytes).unwrap();
        executable_plan.interpreter = None;
        assert_eq!(
            plan_dynamic_program(
                &executable_plan,
                &interpreter_plan,
                0x1000_0040_0000,
                0x1000_2000_0000,
                4096,
            ),
            Err(LoaderError::BadInterpreter)
        );

        let mut nested_interpreter = interpreter_plan;
        nested_interpreter.interpreter = Some("/lib64/ld-linux-x86-64.so.2".into());
        assert_eq!(
            plan_dynamic_program(
                &static_plan,
                &nested_interpreter,
                0x1000_0040_0000,
                0x1000_2000_0000,
                4096,
            ),
            Err(LoaderError::BadInterpreter)
        );
    }

    #[test]
    fn real_bin_true_and_ld_linux_produce_interpreter_entry_frame() {
        let main_bytes = fs::read("/bin/true").unwrap();
        let main_plan = crate::parse(&main_bytes).unwrap();
        let main_image = ImageLayout::new(&main_plan, 0x400000, 4096).unwrap();
        let interpreter_bytes = fs::read("/lib64/ld-linux-x86-64.so.2").unwrap();
        let interpreter_plan = crate::parse(&interpreter_bytes).unwrap();
        let interpreter_image =
            ImageLayout::new(&interpreter_plan, 0x7000_0000_0000, 4096).unwrap();
        let modules = vec![RuntimeModule {
            module_id: 1,
            image: main_image.clone(),
            callbacks: LifecycleCallbacks::default(),
            requires: Vec::new(),
            interpreter_required: true,
        }];
        let plan = ExecutionPlan::new(&modules, 0, Some(&interpreter_image)).unwrap();
        assert_eq!(plan.entry, interpreter_image.entry);
        assert_eq!(plan.program_entry, main_image.entry);
        assert_eq!(plan.entry_source, EntrySource::Interpreter);
        let arg0 = b"/bin/true".as_slice();
        let argv = [arg0];
        let stack = build_initial_stack(
            stack_input_for_program(ProgramStackInput {
                plan: &main_plan,
                image: &main_image,
                interpreter_base: interpreter_image.load_bias,
                stack_top: 0x7fff_0000_0000,
                argv: &argv,
                envp: &[],
                auxv: &[],
                random: None,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            read_aux(&stack, AT_PHDR),
            0x400000 + main_plan.program_headers.unwrap().address
        );
        assert_eq!(read_aux(&stack, AT_ENTRY), main_image.entry);
        assert_eq!(read_aux(&stack, AT_BASE), interpreter_image.load_bias);
        let mut backend = RecordingBackend::default();
        assert_eq!(
            run_preloaded_entry(&mut backend, &plan, stack.clone()),
            Err(LoaderError::BadExecution),
            "interpreter-owned lifecycle must reject the preloaded fast path"
        );
        assert!(backend.calls.is_empty());
        assert!(backend.frame.is_none());
        run_process_entry(&mut backend, &plan, stack).unwrap();
        assert!(
            backend.calls.is_empty(),
            "ld-linux, not the loader shim, owns dynamic initialization"
        );
        let frame = backend.frame.unwrap();
        assert_eq!(frame.pc, interpreter_image.entry);
        assert_eq!(frame.source, EntrySource::Interpreter);
    }

    fn read_u64(stack: &InitialStackPlan, address: u64) -> u64 {
        let offset = usize::try_from(address - stack.stack_pointer).unwrap();
        u64::from_le_bytes(stack.bytes[offset..offset + 8].try_into().unwrap())
    }

    fn string_at(stack: &InitialStackPlan, address: u64) -> &[u8] {
        let offset = usize::try_from(address - stack.stack_pointer).unwrap();
        let end = stack.bytes[offset..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|relative| offset + relative)
            .unwrap();
        &stack.bytes[offset..end]
    }

    fn read_aux(stack: &InitialStackPlan, key: u64) -> u64 {
        let mut cursor = stack.auxv_pointer;
        loop {
            let current_key = read_u64(stack, cursor);
            let value = read_u64(stack, cursor + 8);
            if current_key == key {
                return value;
            }
            if current_key == AT_NULL {
                return 0;
            }
            cursor += 16;
        }
    }
}
