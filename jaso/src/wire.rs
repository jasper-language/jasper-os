//! 隔离模块的通道协议：宿主与隔离进程之间交换的消息（编码 / 解码，无分配）。
//! Wire protocol between a host and the isolated process running a module.
//!
//! # 会话（每条请求恰好一条回复，严格一问一答）
//! 1. 宿主发若干 [`Request::Chunk`]：模块文件的连续片段（单条消息有上限，大文件分片）
//! 2. 宿主发 [`Request::Load`]：信任参数（转交宿主验签时使用的那个发布者）、授予的能力名、
//!    随消息附带的句柄各自对应的能力名；隔离进程**重新**校验并装入模块，再把句柄交给模块
//! 3. 宿主发任意条 [`Request::Call`]：导出名 + 输入字节 + 输出容量；隔离进程调用导出并回复输出字节
//!
//! 通道关闭即会话结束：隔离进程退出；隔离进程崩溃时宿主在下一次收取时看到对端关闭。
//!
//! # 为什么不传指针
//! 两个进程的地址空间互不可见，跨边界只有字节与经授权移动的句柄。导出在隔离运行时须遵守
//! 字节调用约定 [`BytesFn`]。
//!
//! # 格式
//! 小端；字符串为 `u8` 长度 + UTF-8 字节（≤ [`MAX_STR`]）。解码器检查每个长度与取值，多余尾部字节拒绝，从不 panic。

/// 单条消息的字节数上限（与内核通道一致）。
pub const MAX_MESSAGE: usize = 64 * 1024;
/// 单个分片的数据字节数上限（留出消息头）。
pub const MAX_CHUNK: usize = MAX_MESSAGE - 16;
/// 字符串字节数上限。
pub const MAX_STR: usize = 255;
/// 授予的能力名个数上限。
pub const MAX_CAPS: usize = 16;
/// 随 Load 附带的句柄个数上限（与内核通道单条消息的句柄上限一致）。
pub const MAX_HANDLES: usize = 8;

const TAG_CHUNK: u8 = 1;
const TAG_LOAD: u8 = 2;
const TAG_CALL: u8 = 3;
const TAG_REPLY: u8 = 0x80;

/// 隔离运行时导出须遵守的字节调用约定：`(输入, 输入长度, 输出缓冲区, 输出容量) -> 输出长度或负的模块错误码`。
/// The bytes calling convention for exports called across the isolation boundary.
pub type BytesFn = unsafe extern "C" fn(*const u8, usize, *mut u8, usize) -> isize;

/// 绑定句柄的可选导出名：`jaso_bind(能力名指针, 长度, 句柄值) -> 0 成功`。模块要接收句柄就必须导出它。
pub const BIND_SYMBOL: &str = "jaso_bind";
/// [`BIND_SYMBOL`] 的签名。
pub type BindFn = unsafe extern "C" fn(*const u8, usize, u64) -> i32;

/// 转交给隔离进程的信任参数。
/// Trust parameters forwarded to the isolated process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustSpec<'a> {
    /// 必须由这个发布者签名（宿主验签时匹配到的那一个条目）。
    Signed {
        /// 发布者名。
        name: &'a str,
        /// 命名空间。
        namespace: &'a str,
        /// 公钥。
        key: [u8; 32],
    },
    /// 开发模式：允许未签名（隔离进程同样输出审计事件）。
    Development,
}

/// 宿主发往隔离进程的请求。
/// A request from the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request<'a> {
    /// 模块文件的下一个片段。
    Chunk(&'a [u8]),
    /// 校验并装入已收齐的模块文件。
    Load {
        /// 信任参数。
        trust: TrustSpec<'a>,
        /// 授予的能力名（模块清单要求的每一项都必须在其中）。
        caps: Caps<'a>,
        /// 随消息附带的句柄依次对应的能力名。
        handle_caps: Caps<'a>,
    },
    /// 调用一个导出。
    Call {
        /// 导出名。
        export: &'a str,
        /// 输出容量（字节）。
        out_cap: u32,
        /// 输入字节。
        input: &'a [u8],
    },
}

/// 回复的种类。
/// Kind of a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyKind {
    /// 成功：值为 0（分片 / 装入）或导出的返回值（调用；负数是模块自己的错误码）。
    Ok,
    /// 隔离进程拒绝了请求：值为 [`BoxError`] 的编号。
    Refused,
}

/// 隔离进程拒绝请求的原因。
/// Why the isolated process refused a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum BoxError {
    /// 请求无法解码。
    BadRequest = 1,
    /// 模块文件超过上限。
    TooLarge = 2,
    /// 模块未通过校验或装入失败。
    LoadFailed = 3,
    /// 尚未装入模块就调用。
    NotLoaded = 4,
    /// 没有这个导出。
    NoExport = 5,
    /// 导出返回的长度超过输出容量。
    BadOutput = 6,
    /// 已经装入过模块。
    AlreadyLoaded = 7,
    /// 句柄与能力名不匹配、未声明，或模块拒绝绑定。
    BindFailed = 8,
}

impl BoxError {
    /// 由编号还原。
    pub fn from_code(v: i64) -> Option<BoxError> {
        Some(match v {
            1 => BoxError::BadRequest,
            2 => BoxError::TooLarge,
            3 => BoxError::LoadFailed,
            4 => BoxError::NotLoaded,
            5 => BoxError::NoExport,
            6 => BoxError::BadOutput,
            7 => BoxError::AlreadyLoaded,
            8 => BoxError::BindFailed,
            _ => return None,
        })
    }
}

/// 一条回复。
/// A reply from the isolated process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reply<'a> {
    /// 种类。
    pub kind: ReplyKind,
    /// 值。
    pub value: i64,
    /// 输出字节（只有成功的调用有）。
    pub payload: &'a [u8],
}

/// 编解码错误。
/// Encoding or decoding error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// 输入提前结束。
    Truncated,
    /// 未知的消息种类或取值。
    BadTag,
    /// 字符串不是 UTF-8 或超长。
    BadString,
    /// 个数超过上限。
    TooMany,
    /// 解码后还有多余字节。
    Trailing,
    /// 编码时输出缓冲区不够。
    NoRoom,
}

/// 一组能力名（编码后的视图，按需迭代，不分配）。
/// A list of capability names (a view over the encoded bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps<'a> {
    count: usize,
    bytes: &'a [u8],
}

impl<'a> Caps<'a> {
    /// 名字个数。
    pub fn len(&self) -> usize {
        self.count
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// 依次取出各名字（构造时已校验，不会失败）。
    pub fn iter(&self) -> impl Iterator<Item = &'a str> + 'a {
        let mut r = Reader { b: self.bytes, at: 0 };
        (0..self.count).filter_map(move |_| r.str().ok())
    }

    /// 是否包含某个名字。
    pub fn contains(&self, name: &str) -> bool {
        self.iter().any(|c| c == name)
    }

    /// 第 `i` 个名字。
    pub fn get(&self, i: usize) -> Option<&'a str> {
        self.iter().nth(i)
    }
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.at.checked_add(n).ok_or(WireError::Truncated)?;
        let s = self.b.get(self.at..end).ok_or(WireError::Truncated)?;
        self.at = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, WireError> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn i64(&mut self) -> Result<i64, WireError> {
        let s = self.take(8)?;
        let mut v = [0u8; 8];
        v.copy_from_slice(s);
        Ok(i64::from_le_bytes(v))
    }
    fn str(&mut self) -> Result<&'a str, WireError> {
        let n = self.u8()? as usize;
        core::str::from_utf8(self.take(n)?).map_err(|_| WireError::BadString)
    }
    fn caps(&mut self, max: usize) -> Result<Caps<'a>, WireError> {
        let count = self.u8()? as usize;
        if count > max {
            return Err(WireError::TooMany);
        }
        let start = self.at;
        for _ in 0..count {
            self.str()?;
        }
        Ok(Caps { count, bytes: &self.b[start..self.at] })
    }
    fn rest(&mut self) -> &'a [u8] {
        let s = &self.b[self.at..];
        self.at = self.b.len();
        s
    }
    fn end(&self) -> Result<(), WireError> {
        if self.at == self.b.len() {
            Ok(())
        } else {
            Err(WireError::Trailing)
        }
    }
}

/// 编码游标：写入调用者给的缓冲区。
struct Writer<'a> {
    b: &'a mut [u8],
    at: usize,
}

impl Writer<'_> {
    fn put(&mut self, s: &[u8]) -> Result<(), WireError> {
        let end = self.at.checked_add(s.len()).ok_or(WireError::NoRoom)?;
        self.b.get_mut(self.at..end).ok_or(WireError::NoRoom)?.copy_from_slice(s);
        self.at = end;
        Ok(())
    }
    fn str(&mut self, s: &str) -> Result<(), WireError> {
        if s.len() > MAX_STR {
            return Err(WireError::BadString);
        }
        self.put(&[s.len() as u8])?;
        self.put(s.as_bytes())
    }
    fn names(&mut self, names: &[&str], max: usize) -> Result<(), WireError> {
        if names.len() > max {
            return Err(WireError::TooMany);
        }
        self.put(&[names.len() as u8])?;
        names.iter().try_for_each(|n| self.str(n))
    }
}

/// 编码一个分片到 `out`，返回字节数。
/// Encodes a chunk request.
pub fn encode_chunk(data: &[u8], out: &mut [u8]) -> Result<usize, WireError> {
    if data.len() > MAX_CHUNK {
        return Err(WireError::TooMany);
    }
    let mut w = Writer { b: out, at: 0 };
    w.put(&[TAG_CHUNK])?;
    w.put(data)?;
    Ok(w.at)
}

/// 编码装入请求到 `out`，返回字节数。
/// Encodes a load request.
pub fn encode_load(trust: &TrustSpec<'_>, caps: &[&str], handle_caps: &[&str], out: &mut [u8]) -> Result<usize, WireError> {
    let mut w = Writer { b: out, at: 0 };
    w.put(&[TAG_LOAD])?;
    match trust {
        TrustSpec::Signed { name, namespace, key } => {
            w.put(&[1])?;
            w.str(name)?;
            w.str(namespace)?;
            w.put(key)?;
        }
        TrustSpec::Development => w.put(&[0])?,
    }
    w.names(caps, MAX_CAPS)?;
    w.names(handle_caps, MAX_HANDLES)?;
    Ok(w.at)
}

/// 编码调用请求到 `out`，返回字节数。
/// Encodes a call request.
pub fn encode_call(export: &str, out_cap: u32, input: &[u8], out: &mut [u8]) -> Result<usize, WireError> {
    let mut w = Writer { b: out, at: 0 };
    w.put(&[TAG_CALL])?;
    w.str(export)?;
    w.put(&out_cap.to_le_bytes())?;
    w.put(input)?;
    Ok(w.at)
}

/// 编码回复到 `out`，返回字节数。
/// Encodes a reply.
pub fn encode_reply(kind: ReplyKind, value: i64, payload: &[u8], out: &mut [u8]) -> Result<usize, WireError> {
    let mut w = Writer { b: out, at: 0 };
    w.put(&[TAG_REPLY, if kind == ReplyKind::Ok { 0 } else { 1 }])?;
    w.put(&value.to_le_bytes())?;
    w.put(payload)?;
    Ok(w.at)
}

/// 解码一条请求。
/// Decodes a request.
pub fn decode_request(b: &[u8]) -> Result<Request<'_>, WireError> {
    let mut r = Reader { b, at: 0 };
    match r.u8()? {
        TAG_CHUNK => {
            let data = r.rest();
            if data.len() > MAX_CHUNK {
                return Err(WireError::TooMany);
            }
            Ok(Request::Chunk(data))
        }
        TAG_LOAD => {
            let trust = match r.u8()? {
                0 => TrustSpec::Development,
                1 => {
                    let name = r.str()?;
                    let namespace = r.str()?;
                    let mut key = [0u8; 32];
                    key.copy_from_slice(r.take(32)?);
                    TrustSpec::Signed { name, namespace, key }
                }
                _ => return Err(WireError::BadTag),
            };
            let caps = r.caps(MAX_CAPS)?;
            let handle_caps = r.caps(MAX_HANDLES)?;
            r.end()?;
            Ok(Request::Load { trust, caps, handle_caps })
        }
        TAG_CALL => {
            let export = r.str()?;
            let out_cap = r.u32()?;
            Ok(Request::Call { export, out_cap, input: r.rest() })
        }
        _ => Err(WireError::BadTag),
    }
}

/// 解码一条回复。
/// Decodes a reply.
pub fn decode_reply(b: &[u8]) -> Result<Reply<'_>, WireError> {
    let mut r = Reader { b, at: 0 };
    if r.u8()? != TAG_REPLY {
        return Err(WireError::BadTag);
    }
    let kind = match r.u8()? {
        0 => ReplyKind::Ok,
        1 => ReplyKind::Refused,
        _ => return Err(WireError::BadTag),
    };
    let value = r.i64()?;
    Ok(Reply { kind, value, payload: r.rest() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_roundtrip_all_messages() {
        let mut buf = [0u8; 1024];
        let n = encode_chunk(b"abc", &mut buf).unwrap();
        assert_eq!(decode_request(&buf[..n]), Ok(Request::Chunk(b"abc")));

        let trust = TrustSpec::Signed { name: "jasper.dev", namespace: "jaso-", key: [7; 32] };
        let n = encode_load(&trust, &["system.console.write", "system.task.wait"], &["system.task.wait"], &mut buf).unwrap();
        match decode_request(&buf[..n]).unwrap() {
            Request::Load { trust: t, caps, handle_caps } => {
                assert_eq!(t, trust);
                assert_eq!(caps.len(), 2);
                assert!(caps.contains("system.task.wait") && !caps.contains("system.task"));
                assert_eq!(handle_caps.get(0), Some("system.task.wait"));
                assert_eq!(handle_caps.get(1), None);
            }
            other => panic!("{:?}", other),
        }
        let n = encode_load(&TrustSpec::Development, &[], &[], &mut buf).unwrap();
        match decode_request(&buf[..n]).unwrap() {
            Request::Load { trust, caps, handle_caps } => {
                assert_eq!(trust, TrustSpec::Development);
                assert!(caps.is_empty() && handle_caps.is_empty());
            }
            other => panic!("{:?}", other),
        }

        let n = encode_call("probe_sum", 64, &[1, 2, 3], &mut buf).unwrap();
        assert_eq!(decode_request(&buf[..n]), Ok(Request::Call { export: "probe_sum", out_cap: 64, input: &[1, 2, 3] }));

        let n = encode_reply(ReplyKind::Refused, BoxError::NoExport as i64, &[], &mut buf).unwrap();
        let r = decode_reply(&buf[..n]).unwrap();
        assert_eq!((r.kind, BoxError::from_code(r.value)), (ReplyKind::Refused, Some(BoxError::NoExport)));
        let n = encode_reply(ReplyKind::Ok, -5, b"xy", &mut buf).unwrap();
        assert_eq!(decode_reply(&buf[..n]), Ok(Reply { kind: ReplyKind::Ok, value: -5, payload: b"xy" }));
    }

    #[test]
    fn wire_rejects_malformed_input() {
        let mut buf = [0u8; 512];
        assert_eq!(decode_request(&[]), Err(WireError::Truncated));
        assert_eq!(decode_request(&[9]), Err(WireError::BadTag));
        assert_eq!(decode_reply(&[TAG_REPLY, 2, 0, 0, 0, 0, 0, 0, 0, 0]), Err(WireError::BadTag));
        assert_eq!(decode_reply(&[TAG_REPLY, 0, 1]), Err(WireError::Truncated));
        // Load：尾部多余字节、信任种类未知、字符串截断、非 UTF-8、能力个数超限
        let n = encode_load(&TrustSpec::Development, &["a"], &[], &mut buf).unwrap();
        let mut v = buf[..n].to_vec();
        v.push(0);
        assert_eq!(decode_request(&v), Err(WireError::Trailing));
        assert_eq!(decode_request(&[TAG_LOAD, 5]), Err(WireError::BadTag));
        assert_eq!(decode_request(&[TAG_LOAD, 1, 10, b'a']), Err(WireError::Truncated));
        assert_eq!(decode_request(&[TAG_LOAD, 0, 1, 2, 0xff, 0xfe, 0]), Err(WireError::BadString));
        assert_eq!(decode_request(&[TAG_LOAD, 0, (MAX_CAPS + 1) as u8]), Err(WireError::TooMany));
        assert_eq!(decode_request(&[TAG_LOAD, 0, 0, (MAX_HANDLES + 1) as u8]), Err(WireError::TooMany));
        // 编码侧：超长字符串、超多名字、缓冲区不足、超大分片
        let long = "x".repeat(MAX_STR + 1);
        assert_eq!(encode_call(&long, 0, &[], &mut buf), Err(WireError::BadString));
        let many = ["c"; MAX_CAPS + 1];
        assert_eq!(encode_load(&TrustSpec::Development, &many, &[], &mut buf), Err(WireError::TooMany));
        assert_eq!(encode_call("e", 0, &[0; 600], &mut buf), Err(WireError::NoRoom));
        let mut big = vec![0u8; MAX_MESSAGE + 8];
        assert_eq!(encode_chunk(&vec![0u8; MAX_CHUNK + 1], &mut big), Err(WireError::TooMany));
        assert_eq!(decode_request(&{ let mut m = vec![TAG_CHUNK]; m.extend(vec![0u8; MAX_CHUNK + 1]); m }), Err(WireError::TooMany));
    }

    #[test]
    fn wire_random_bytes_never_panic() {
        // 固定种子的随机输入：解码只返回结果或错误
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let len = (x % 80) as usize;
            let mut v = vec![0u8; len];
            for (i, b) in v.iter_mut().enumerate() {
                *b = (x >> ((i % 8) * 8)) as u8 ^ i as u8;
            }
            if !v.is_empty() {
                v[0] = [TAG_CHUNK, TAG_LOAD, TAG_CALL, TAG_REPLY][(x >> 3) as usize % 4];
            }
            let _ = decode_request(&v);
            let _ = decode_reply(&v);
            if let Ok(Request::Load { caps, handle_caps, .. }) = decode_request(&v) {
                assert!(caps.iter().count() == caps.len() && handle_caps.iter().count() == handle_caps.len());
            }
        }
    }
}
