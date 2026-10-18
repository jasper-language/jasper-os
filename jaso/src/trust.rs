//! 发布者信任策略：受信发布者表 + 验签，决定一个格式合格的 `.jaso` 是否可以装载。
//! Publisher trust policy: the trusted-publisher table and signature verification.
//!
//! # 职责与边界
//! * [`crate::Image::parse`] 只证明「文件结构合法、内容未被改动」；本模块证明「内容出自受信的发布者」。
//! * 装载器必须在映射任何内容之前调用 [`TrustPolicy::verify`]，失败即拒绝、无副作用。
//! * 本模块只做验签（no_std、不分配）；签名在宿主打包侧完成（`sign` 特性下的 [`crate::build::Signer`]）。
//!
//! # 判定规则（按顺序，第一条不满足即拒绝）
//! 1. 没有签名段：强制模式拒绝（[`TrustError::Unsigned`]）；开发模式接受为 [`Provenance::UnsignedDevelopment`]，
//!    由调用者负责把这次放行记入审计（装载器输出一条结构化审计事件）
//! 2. 清单必须声明 `core.publisher`，且该名字在受信发布者表中
//! 3. 签名段里的公钥必须与表中该发布者的公钥逐字节一致（换发布者 / 用别人的密钥重签都在这里被拒）
//! 4. 模块名必须落在该发布者的命名空间（名字前缀）内：受信发布者也不能冒用别人的模块名
//! 5. Ed25519 严格验签（拒绝非规范编码与小阶点），消息为 [`crate::SIGNATURE_DOMAIN`] ‖ 签名覆盖摘要
//!
//! 开发模式只放宽第 1 条：带签名的模块无论在哪种模式下都要通过 2–5，坏签名永远不会被放行。

use ed25519_dalek::{Signature, VerifyingKey};

use crate::{signed_message, Image};

/// 开发用发布者名：工作区内置模块的清单都以它声明 `core.publisher`（签名密钥是公开的，只用于开发与验收）。
/// Name of the development publisher used by the in-tree modules (its signing key is public).
pub const DEVELOPMENT_PUBLISHER: &str = "jasper.dev";
/// 开发用发布者的命名空间（模块名前缀）。
/// Namespace (module-name prefix) of the development publisher.
pub const DEVELOPMENT_NAMESPACE: &str = "jaso-";

/// 一个受信发布者。
/// A trusted publisher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Publisher<'a> {
    /// 发布者名（与清单 `core.publisher` 比对）。
    pub name: &'a str,
    /// 命名空间：该发布者可以签发的模块名前缀（空串表示不限）。
    pub namespace: &'a str,
    /// Ed25519 公钥（32 字节压缩编码）。
    pub key: [u8; 32],
}

/// 信任模式。
/// Trust mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustMode {
    /// 强制：未签名模块一律拒绝（默认、生产用）。
    Enforce,
    /// 开发：允许未签名模块，但每次放行都必须被审计；带签名的模块仍按强制规则校验。
    Development,
}

/// 构造策略时发现的问题。
/// Errors found while building a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    /// 发布者名为空。
    EmptyName,
    /// 两个条目用了同一个发布者名（查找会有歧义）。
    DuplicatePublisher,
    /// 公钥不是合法的曲线点编码。
    BadKey,
}

/// 验签失败的原因。
/// Why a module was not trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustError {
    /// 没有签名段（强制模式）。
    Unsigned,
    /// 有签名，但清单没有声明 `core.publisher`。
    MissingPublisher,
    /// 声明的发布者不在受信表中。
    UnknownPublisher,
    /// 签名段里的公钥与受信表中该发布者的公钥不一致。
    KeyMismatch,
    /// 模块名不在该发布者的命名空间内。
    OutOfNamespace,
    /// 签名值无效（内容在签名之后被改动、签名被替换，或编码不规范）。
    BadSignature,
}

/// 通过验证后的来源。
/// The provenance of a module that passed the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance<'a> {
    /// 由受信发布者签名。
    Signed {
        /// 发布者名（取自受信表）。
        publisher: &'a str,
    },
    /// 未签名，仅因开发模式被放行（必须审计）。
    UnsignedDevelopment,
}

/// 受信发布者表 + 信任模式。
/// The trusted-publisher table plus the trust mode.
#[derive(Debug, Clone, Copy)]
pub struct TrustPolicy<'a> {
    publishers: &'a [Publisher<'a>],
    mode: TrustMode,
}

impl<'a> TrustPolicy<'a> {
    /// 校验并建立策略：发布者名非空且互不相同，公钥都是合法的曲线点。
    /// Validates and builds a policy.
    pub fn new(publishers: &'a [Publisher<'a>], mode: TrustMode) -> Result<TrustPolicy<'a>, PolicyError> {
        for (i, p) in publishers.iter().enumerate() {
            if p.name.is_empty() {
                return Err(PolicyError::EmptyName);
            }
            if publishers[..i].iter().any(|q| q.name == p.name) {
                return Err(PolicyError::DuplicatePublisher);
            }
            if VerifyingKey::from_bytes(&p.key).is_err() {
                return Err(PolicyError::BadKey);
            }
        }
        Ok(TrustPolicy { publishers, mode })
    }

    /// 信任模式。
    /// The trust mode.
    pub fn mode(&self) -> TrustMode {
        self.mode
    }

    /// 受信发布者表。
    /// The trusted publishers.
    pub fn publishers(&self) -> &'a [Publisher<'a>] {
        self.publishers
    }

    /// 按模块文档的规则判定 `img` 是否可信；不修改任何状态。
    /// Decides whether `img` is trusted; has no side effects.
    pub fn verify(&self, img: &Image<'_>) -> Result<Provenance<'a>, TrustError> {
        let (Some(sig), Some(digest)) = (img.signature(), img.signed_digest()) else {
            return match self.mode {
                TrustMode::Enforce => Err(TrustError::Unsigned),
                TrustMode::Development => Ok(Provenance::UnsignedDevelopment),
            };
        };
        let name = img.manifest.publisher.ok_or(TrustError::MissingPublisher)?;
        let p = self.publishers.iter().find(|p| p.name == name).ok_or(TrustError::UnknownPublisher)?;
        if p.key != sig.publisher_key {
            return Err(TrustError::KeyMismatch);
        }
        if !img.manifest.name.starts_with(p.namespace) {
            return Err(TrustError::OutOfNamespace);
        }
        // 公钥在 new() 中已证明可解码；这里仍按失败处理，不 panic
        let key = VerifyingKey::from_bytes(&p.key).map_err(|_| TrustError::BadSignature)?;
        let signature = Signature::from_bytes(&sig.signature);
        key.verify_strict(&signed_message(&digest), &signature).map_err(|_| TrustError::BadSignature)?;
        Ok(Provenance::Signed { publisher: p.name })
    }
}
