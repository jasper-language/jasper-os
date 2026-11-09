//! `jasper.source` version 1 payload.
//!
//! The core format stores source text as an optional extension. This module
//! defines the interoperable envelope while leaving the actual compressor and
//! decompressor outside the core reader.

#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::u32_at;

/// Extension name for embedded source.
pub const EXTENSION: &str = crate::EXT_JASPER_SOURCE;
/// The only language identifier defined by version 1.
pub const LANGUAGE_JASPER: u8 = 1;
/// No compression; storage bytes are the logical source bytes.
pub const COMPRESSION_NONE: u8 = 0;
/// RFC 1950 zlib stream.
pub const COMPRESSION_ZLIB: u8 = 1;
/// Maximum logical source length after decompression.
pub const MAX_LOGICAL_BYTES: usize = 4 * 1024 * 1024;
/// Maximum stored payload length in the extension.
pub const MAX_STORED_BYTES: usize = 1024 * 1024;

const MAGIC: &[u8; 4] = b"JSRC";
const ENVELOPE_VERSION: u8 = 1;
const HEADER_BYTES: usize = 16;

/// Why a `jasper.source` envelope or decoding request was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceError {
    /// The fixed header, version, or reserved fields are malformed.
    Malformed,
    /// The language identifier is not defined by version 1.
    Language,
    /// The compression identifier is not defined by version 1.
    Compression,
    /// Stored or logical length does not match the envelope.
    Length,
    /// A configured source limit was exceeded.
    Limit,
    /// The supplied decompressor rejected the compressed bytes.
    Decompress,
    /// The decompressor did not produce exactly the declared logical length.
    DecompressedLength,
}

impl SourceError {
    /// Stable diagnostic name for host tooling and tests.
    pub const fn name(self) -> &'static str {
        match self {
            SourceError::Malformed => "source.malformed",
            SourceError::Language => "source.language",
            SourceError::Compression => "source.compression",
            SourceError::Length => "source.length",
            SourceError::Limit => "source.limit",
            SourceError::Decompress => "source.decompress",
            SourceError::DecompressedLength => "source.decompressed_length",
        }
    }
}

/// Parsed `jasper.source` v1 envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceV1<'a> {
    language: u8,
    compression: u8,
    logical_len: u32,
    stored: &'a [u8],
}

impl<'a> SourceV1<'a> {
    /// Source language identifier.
    pub const fn language(self) -> u8 {
        self.language
    }

    /// Compression identifier.
    pub const fn compression(self) -> u8 {
        self.compression
    }

    /// Declared source length before decompression.
    pub const fn logical_len(self) -> u32 {
        self.logical_len
    }

    /// Stored bytes following the 16-byte envelope.
    pub const fn stored(self) -> &'a [u8] {
        self.stored
    }
}

/// A decoded source payload, either borrowed when stored uncompressed or
/// allocated when produced by a decompressor.
#[cfg(feature = "alloc")]
#[derive(Debug, PartialEq, Eq)]
pub enum DecodedSource<'a> {
    /// Uncompressed bytes borrowed directly from the `.jaso` file.
    Borrowed(&'a [u8]),
    /// Decompressed bytes owned by the caller.
    Owned(Vec<u8>),
}

#[cfg(feature = "alloc")]
impl DecodedSource<'_> {
    /// View the decoded source bytes.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            DecodedSource::Borrowed(bytes) => bytes,
            DecodedSource::Owned(bytes) => bytes,
        }
    }
}

#[cfg(feature = "alloc")]
impl<'a> SourceV1<'a> {
    /// Decode the source.
    ///
    /// For `COMPRESSION_NONE`, the result is borrowed and requires no callback.
    /// For `COMPRESSION_ZLIB`, `decompress` must decode a complete zlib stream
    /// into the supplied output buffer and return exactly its logical length.
    /// Returning `None` is reported as [`SourceError::Decompress`].
    pub fn decode(
        self,
        decompress: impl FnOnce(&[u8], &mut [u8]) -> Option<usize>,
    ) -> Result<DecodedSource<'a>, SourceError> {
        match self.compression {
            COMPRESSION_NONE => Ok(DecodedSource::Borrowed(self.stored)),
            COMPRESSION_ZLIB => {
                let mut out = vec![0u8; self.logical_len as usize];
                let written = decompress(self.stored, &mut out).ok_or(SourceError::Decompress)?;
                if written != out.len() {
                    return Err(SourceError::DecompressedLength);
                }
                Ok(DecodedSource::Owned(out))
            }
            _ => Err(SourceError::Compression),
        }
    }
}

/// Parse and validate a `jasper.source` v1 extension payload.
pub fn parse(content: &[u8]) -> Result<SourceV1<'_>, SourceError> {
    if content.len() < HEADER_BYTES
        || &content[..4] != MAGIC
        || content[4] != ENVELOPE_VERSION
        || content[7] != 0
    {
        return Err(SourceError::Malformed);
    }
    let language = content[5];
    if language != LANGUAGE_JASPER {
        return Err(SourceError::Language);
    }
    let compression = content[6];
    if !matches!(compression, COMPRESSION_NONE | COMPRESSION_ZLIB) {
        return Err(SourceError::Compression);
    }
    let logical_len = u32_at(content, 8) as usize;
    let stored_len = u32_at(content, 12) as usize;
    if logical_len > MAX_LOGICAL_BYTES || stored_len > MAX_STORED_BYTES {
        return Err(SourceError::Limit);
    }
    if content.len() != HEADER_BYTES + stored_len {
        return Err(SourceError::Length);
    }
    if compression == COMPRESSION_NONE && logical_len != stored_len {
        return Err(SourceError::Length);
    }
    Ok(SourceV1 {
        language,
        compression,
        logical_len: logical_len as u32,
        stored: &content[HEADER_BYTES..],
    })
}

/// Encode a validated `jasper.source` v1 envelope.
#[cfg(feature = "alloc")]
pub fn encode(
    language: u8,
    compression: u8,
    logical_len: u32,
    stored: &[u8],
) -> Result<Vec<u8>, SourceError> {
    let logical = logical_len as usize;
    if logical > MAX_LOGICAL_BYTES || stored.len() > MAX_STORED_BYTES {
        return Err(SourceError::Limit);
    }
    if language != LANGUAGE_JASPER {
        return Err(SourceError::Language);
    }
    if !matches!(compression, COMPRESSION_NONE | COMPRESSION_ZLIB) {
        return Err(SourceError::Compression);
    }
    if compression == COMPRESSION_NONE && logical != stored.len() {
        return Err(SourceError::Length);
    }
    let mut out = Vec::with_capacity(HEADER_BYTES + stored.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&[ENVELOPE_VERSION, language, compression, 0]);
    out.extend_from_slice(&logical_len.to_le_bytes());
    out.extend_from_slice(&(stored.len() as u32).to_le_bytes());
    out.extend_from_slice(stored);
    Ok(out)
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    #[test]
    fn uncompressed_roundtrip_is_borrowed() {
        let text = b"module example\n";
        let bytes = encode(LANGUAGE_JASPER, COMPRESSION_NONE, text.len() as u32, text).unwrap();
        let source = parse(&bytes).unwrap();
        assert_eq!(source.language(), LANGUAGE_JASPER);
        assert_eq!(source.logical_len(), text.len() as u32);
        let decoded = source.decode(|_, _| None).unwrap();
        assert!(matches!(decoded, DecodedSource::Borrowed(_)));
        assert_eq!(decoded.as_bytes(), text);
    }

    #[test]
    fn zlib_decoder_must_succeed_and_match_declared_length() {
        let bytes = encode(LANGUAGE_JASPER, COMPRESSION_ZLIB, 4, b"z").unwrap();
        let source = parse(&bytes).unwrap();
        assert_eq!(source.decode(|_, _| None), Err(SourceError::Decompress));
        assert_eq!(
            source.decode(|_, _| Some(3)),
            Err(SourceError::DecompressedLength)
        );
        let decoded = source
            .decode(|stored, out| {
                assert_eq!(stored, b"z");
                out.copy_from_slice(b"test");
                Some(out.len())
            })
            .unwrap();
        assert_eq!(decoded.as_bytes(), b"test");
    }

    #[test]
    fn malformed_unknown_and_length_cases_are_rejected() {
        let good = encode(LANGUAGE_JASPER, COMPRESSION_NONE, 1, b"x").unwrap();
        assert_eq!(parse(&good[..HEADER_BYTES - 1]), Err(SourceError::Malformed));

        let mut language = good.clone();
        language[5] = 2;
        assert_eq!(parse(&language), Err(SourceError::Language));

        let mut compression = good.clone();
        compression[6] = 2;
        assert_eq!(parse(&compression), Err(SourceError::Compression));

        let mut flags = good.clone();
        flags[7] = 1;
        assert_eq!(parse(&flags), Err(SourceError::Malformed));

        let mut stored = good.clone();
        stored[12..16].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(parse(&stored), Err(SourceError::Length));

        let mut mismatch = good;
        mismatch[8..12].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(parse(&mismatch), Err(SourceError::Length));
    }

    #[test]
    fn limits_and_encoding_rejections_are_atomic() {
        assert_eq!(
            encode(LANGUAGE_JASPER, COMPRESSION_NONE, 2, b"x"),
            Err(SourceError::Length)
        );
        assert_eq!(
            encode(2, COMPRESSION_NONE, 1, b"x"),
            Err(SourceError::Language)
        );
        assert_eq!(
            encode(LANGUAGE_JASPER, 2, 1, b"x"),
            Err(SourceError::Compression)
        );
        assert_eq!(
            encode(
                LANGUAGE_JASPER,
                COMPRESSION_ZLIB,
                (MAX_LOGICAL_BYTES + 1) as u32,
                b"x"
            ),
            Err(SourceError::Limit)
        );
    }
}
