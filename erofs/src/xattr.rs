//! Extended attributes (xattrs).
//!
//! EROFS stores xattrs in two places:
//!
//! - **Inline**, right after the on-disk inode: an ibody header
//!   (`XattrHeader`, 12 bytes) followed by `shared_count` little-endian `u32`
//!   shared-xattr ids, followed by inline entries up to the end of the
//!   `Inode::xattr_size()` area.
//! - **Shared**, in the xattr area starting at `SuperBlock::xattr_blk_addr`.
//!   A shared id is a 4-byte-unit offset into that area. Identical xattrs
//!   used by many inodes (for example one SELinux label on a whole tree) are
//!   stored once there.
//!
//! Every entry is an `XattrEntry` (4 bytes) followed by the name suffix and
//! the value, padded to a 4-byte boundary. The full name is a prefix chosen by
//! `name_index` plus the stored suffix. With the `xattr_prefixes` feature a
//! `name_index` with bit 7 set selects a *long prefix* from a table at
//! `SuperBlock::xattr_prefix_start * 4`, which itself extends one of the
//! built-in prefixes with an infix.
//!
//! Android stores SELinux labels as `security.selinux`, so this is what
//! [`crate::EroFS::get_xattr`] with `b"security.selinux"` returns for system
//! images.
//!
//! The layout follows `fs/erofs/xattr.c` in Linux and `lib/xattr.c` in
//! erofs-utils. Like the kernel, `xattrs()` lists inline entries first, then
//! shared ones, and skips entries whose prefix index it does not know.

use alloc::vec::Vec;

use crate::{Error, Result};

pub const XATTR_INDEX_USER: u8 = 1;
pub const XATTR_INDEX_POSIX_ACL_ACCESS: u8 = 2;
pub const XATTR_INDEX_POSIX_ACL_DEFAULT: u8 = 3;
pub const XATTR_INDEX_TRUSTED: u8 = 4;
pub const XATTR_INDEX_LUSTRE: u8 = 5;
pub const XATTR_INDEX_SECURITY: u8 = 6;

/// `name_index` bit marking a long (table-based) prefix.
pub const XATTR_LONG_PREFIX: u8 = 0x80;
pub const XATTR_LONG_PREFIX_MASK: u8 = 0x7f;

/// Size of the inline ibody header (`erofs_xattr_ibody_header`).
pub const XATTR_IBODY_HEADER_SIZE: usize = 12;
/// Size of an entry header (`erofs_xattr_entry`).
pub const XATTR_ENTRY_SIZE: usize = 4;

pub(crate) const FEATURE_COMPAT_SHARED_EA_IN_METABOX: u32 = 0x0000_0008;
pub(crate) const FEATURE_COMPAT_PLAIN_XATTR_PFX: u32 = 0x0000_0010;

/// One extended attribute: full name (prefix included) and raw value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xattr {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

impl Xattr {
    /// The name as UTF-8, if it is valid UTF-8.
    pub fn name_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.name).ok()
    }
}

/// An entry from the long xattr name prefix table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongPrefix {
    /// Built-in prefix index the infix extends.
    pub base_index: u8,
    pub infix: Vec<u8>,
}

/// The name prefix for a built-in `name_index`.
///
/// Index 0 has no prefix (the full name is stored). Lustre (5) and unknown
/// indexes return `None`; the kernel does not expose those either.
pub fn builtin_prefix(index: u8) -> Option<&'static [u8]> {
    match index {
        0 => Some(b""),
        XATTR_INDEX_USER => Some(b"user."),
        XATTR_INDEX_POSIX_ACL_ACCESS => Some(b"system.posix_acl_access"),
        XATTR_INDEX_POSIX_ACL_DEFAULT => Some(b"system.posix_acl_default"),
        XATTR_INDEX_TRUSTED => Some(b"trusted."),
        XATTR_INDEX_SECURITY => Some(b"security."),
        _ => None,
    }
}

#[inline]
pub(crate) const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Parse the inline ibody header. Returns the shared xattr ids and the
/// offset (within `body`) where inline entries start.
///
/// `body` must be exactly the inode's xattr area (`Inode::xattr_size()`).
pub(crate) fn parse_ibody(body: &[u8]) -> Result<(Vec<u32>, usize)> {
    if body.len() < XATTR_IBODY_HEADER_SIZE {
        return Err(Error::CorruptedData(format!(
            "xattr ibody too small: {} bytes",
            body.len()
        )));
    }
    let shared_count = body[4] as usize;
    let entries_start = XATTR_IBODY_HEADER_SIZE + shared_count * 4;
    if entries_start > body.len() {
        return Err(Error::CorruptedData(format!(
            "xattr ibody: {} shared ids overflow {} byte area",
            shared_count,
            body.len()
        )));
    }
    let ids = body[XATTR_IBODY_HEADER_SIZE..entries_start]
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    Ok((ids, entries_start))
}

/// Header of one xattr entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EntryHeader {
    pub name_len: usize,
    pub name_index: u8,
    pub value_len: usize,
}

impl EntryHeader {
    pub(crate) fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < XATTR_ENTRY_SIZE {
            return Err(Error::CorruptedData("truncated xattr entry".into()));
        }
        Ok(Self {
            name_len: data[0] as usize,
            name_index: data[1],
            value_len: u16::from_le_bytes([data[2], data[3]]) as usize,
        })
    }

    /// Unpadded size of header + name + value.
    pub(crate) const fn body_len(&self) -> usize {
        XATTR_ENTRY_SIZE + self.name_len + self.value_len
    }

    /// On-disk size including padding to 4 bytes.
    pub(crate) const fn disk_len(&self) -> usize {
        align4(self.body_len())
    }
}

/// Parse one entry at the start of `data`.
/// Returns (header, name suffix, value).
pub(crate) fn parse_entry(data: &[u8]) -> Result<(EntryHeader, &[u8], &[u8])> {
    let h = EntryHeader::parse(data)?;
    if data.len() < h.body_len() {
        return Err(Error::CorruptedData(format!(
            "xattr entry needs {} bytes, {} available",
            h.body_len(),
            data.len()
        )));
    }
    let name = &data[XATTR_ENTRY_SIZE..XATTR_ENTRY_SIZE + h.name_len];
    let value = &data[XATTR_ENTRY_SIZE + h.name_len..h.body_len()];
    Ok((h, name, value))
}

/// Build the full name for an entry. Returns `Ok(None)` for prefixes the
/// kernel would skip (unknown built-in index).
pub(crate) fn full_name(
    name_index: u8,
    suffix: &[u8],
    long_prefixes: &[LongPrefix],
) -> Result<Option<Vec<u8>>> {
    if name_index & XATTR_LONG_PREFIX != 0 {
        let idx = (name_index & XATTR_LONG_PREFIX_MASK) as usize;
        let lp = long_prefixes.get(idx).ok_or_else(|| {
            Error::CorruptedData(format!(
                "xattr long prefix {} out of {}",
                idx,
                long_prefixes.len()
            ))
        })?;
        let base = builtin_prefix(lp.base_index).ok_or_else(|| {
            Error::CorruptedData(format!(
                "xattr long prefix {} has bad base index {}",
                idx, lp.base_index
            ))
        })?;
        let mut name = Vec::with_capacity(base.len() + lp.infix.len() + suffix.len());
        name.extend_from_slice(base);
        name.extend_from_slice(&lp.infix);
        name.extend_from_slice(suffix);
        return Ok(Some(name));
    }
    Ok(builtin_prefix(name_index).map(|base| {
        let mut name = Vec::with_capacity(base.len() + suffix.len());
        name.extend_from_slice(base);
        name.extend_from_slice(suffix);
        name
    }))
}

/// Parse a long prefix record payload (`erofs_xattr_long_prefix`): one byte
/// base index followed by the infix.
pub(crate) fn parse_long_prefix(payload: &[u8]) -> Result<LongPrefix> {
    // EROFS_NAME_LEN (255) + 1 byte base_index is the upper bound in erofs-utils.
    if payload.is_empty() || payload.len() > 256 {
        return Err(Error::CorruptedData(format!(
            "bad xattr long prefix length {}",
            payload.len()
        )));
    }
    Ok(LongPrefix {
        base_index: payload[0],
        infix: payload[1..].to_vec(),
    })
}

/// Parse inline entries in `entries` (everything after the shared ids) and
/// append them to `out`.
pub(crate) fn parse_inline_entries(
    mut entries: &[u8],
    long_prefixes: &[LongPrefix],
    out: &mut Vec<Xattr>,
) -> Result<()> {
    // The area is padded; a run shorter than an entry header is padding.
    while entries.len() >= XATTR_ENTRY_SIZE {
        let (h, suffix, value) = parse_entry(entries)?;
        if let Some(name) = full_name(h.name_index, suffix, long_prefixes)? {
            out.push(Xattr {
                name,
                value: value.to_vec(),
            });
        }
        entries = &entries[h.disk_len().min(entries.len())..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(index: u8, name: &[u8], value: &[u8]) -> Vec<u8> {
        let mut v = vec![name.len() as u8, index];
        v.extend_from_slice(&(value.len() as u16).to_le_bytes());
        v.extend_from_slice(name);
        v.extend_from_slice(value);
        v.resize(align4(v.len()), 0);
        v
    }

    #[test]
    fn builtin_prefixes_match_erofs_utils() {
        assert_eq!(builtin_prefix(0), Some(&b""[..]));
        assert_eq!(builtin_prefix(XATTR_INDEX_USER), Some(&b"user."[..]));
        assert_eq!(
            builtin_prefix(XATTR_INDEX_SECURITY),
            Some(&b"security."[..])
        );
        assert_eq!(builtin_prefix(XATTR_INDEX_LUSTRE), None);
        assert_eq!(builtin_prefix(42), None);
    }

    #[test]
    fn ibody_header_and_shared_ids() {
        let mut body = vec![0u8; 12];
        body[4] = 2;
        body.extend_from_slice(&7u32.to_le_bytes());
        body.extend_from_slice(&9u32.to_le_bytes());
        let (ids, start) = parse_ibody(&body).unwrap();
        assert_eq!(ids, vec![7, 9]);
        assert_eq!(start, 20);
    }

    #[test]
    fn ibody_rejects_overflowing_shared_count() {
        let mut body = vec![0u8; 16];
        body[4] = 2; // needs 20 bytes
        assert!(parse_ibody(&body).is_err());
        assert!(parse_ibody(&[0u8; 8]).is_err());
    }

    #[test]
    fn inline_entries_with_padding_and_unknown_prefix() {
        let mut data = entry(
            XATTR_INDEX_SECURITY,
            b"selinux",
            b"u:object_r:system_file:s0",
        );
        data.extend(entry(XATTR_INDEX_LUSTRE, b"skip", b"x"));
        data.extend(entry(XATTR_INDEX_USER, b"k", b""));
        let mut out = Vec::new();
        parse_inline_entries(&data, &[], &mut out).unwrap();
        assert_eq!(
            out,
            vec![
                Xattr {
                    name: b"security.selinux".to_vec(),
                    value: b"u:object_r:system_file:s0".to_vec()
                },
                Xattr {
                    name: b"user.k".to_vec(),
                    value: vec![]
                },
            ]
        );
    }

    #[test]
    fn truncated_entry_is_corruption() {
        let mut data = entry(XATTR_INDEX_USER, b"name", b"value");
        data.truncate(8);
        let mut out = Vec::new();
        assert!(parse_inline_entries(&data, &[], &mut out).is_err());
    }

    #[test]
    fn long_prefix_name() {
        let lps = vec![LongPrefix {
            base_index: XATTR_INDEX_SECURITY,
            infix: b"sel".to_vec(),
        }];
        assert_eq!(
            full_name(XATTR_LONG_PREFIX, b"inux", &lps).unwrap(),
            Some(b"security.selinux".to_vec())
        );
        assert!(full_name(XATTR_LONG_PREFIX | 1, b"x", &lps).is_err());
        assert!(parse_long_prefix(&[]).is_err());
        assert_eq!(
            parse_long_prefix(b"\x06sel").unwrap(),
            LongPrefix {
                base_index: 6,
                infix: b"sel".to_vec()
            }
        );
    }
}
