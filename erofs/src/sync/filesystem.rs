use alloc::{format, string::ToString, sync::Arc, vec::Vec};
use bytes::Buf;
use typed_path::Component;
use typed_path::{UnixComponent, UnixPath};

use super::file::File;
use super::walkdir::WalkDir;
use crate::backend::Image;
use crate::dirent;
use crate::filesystem::{BlockPlan, EroFSCore};
use crate::types::*;
use crate::xattr::{self, LongPrefix, Xattr};
use crate::{Error, Result};

/// The main entry point for reading EROFS filesystem images.
///
/// `EroFS` provides methods to traverse directories, open files, and access
/// filesystem metadata from EROFS images. It supports both standard (mmap-based)
/// and no_std (slice-based) backends.
///
/// # Examples
///
/// ## Standard usage with mmap
///
/// ```no_run
/// use std::io::Read;
/// use erofs_rs::{EroFS, backend::MmapImage};
///
/// let image = MmapImage::new_from_path("image.erofs").unwrap();
/// let fs = EroFS::new(image).unwrap();
///
/// let mut file = fs.open("/etc/passwd").unwrap();
/// let mut content = String::new();
/// file.read_to_string(&mut content).unwrap();
/// ```
///
/// ## no_std usage with byte slice
///
/// ```no_run
/// # extern crate alloc;
/// use erofs_rs::{EroFS, backend::SliceImage};
///
/// let image_data: &'static [u8] = &[/* EROFS image data */];
/// let fs = EroFS::new(SliceImage::new(image_data)).unwrap();
///
/// // Traverse directories
/// for entry in fs.read_dir("/etc").unwrap() {
///     let entry = entry.unwrap();
///     // Process directory entry...
/// }
/// ```
#[derive(Debug, Clone)]
pub struct EroFS<I: Image> {
    image: Arc<I>,
    core: EroFSCore,
}

impl<I: Image> EroFS<I> {
    /// Creates a new `EroFS` instance from a backend image source.
    ///
    /// The backend can be either a memory-mapped file ([`MmapImage`](crate::backend::MmapImage))
    /// in std environments, or a byte slice ([`SliceImage`](crate::backend::SliceImage)) in
    /// no_std environments.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The superblock cannot be read
    /// - The magic number doesn't match EROFS format (0xE0F5E1E2)
    /// - The block size is invalid (must be 2^n where 9 ≤ n ≤ 24)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use erofs_rs::{EroFS, backend::MmapImage};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let image = MmapImage::new_from_path("image.erofs")?;
    /// let fs = EroFS::new(image)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(image: I) -> Result<Self> {
        let sb_data = image
            .get(SUPER_BLOCK_OFFSET..)
            .ok_or_else(|| Error::InvalidSuperblock("failed to read super block".to_string()))?;
        let core = EroFSCore::new(sb_data)?;
        Ok(Self {
            image: image.into(),
            core,
        })
    }

    /// Recursively walks a directory tree starting from the given path.
    ///
    /// Returns an iterator that yields all entries (files and directories)
    /// under the specified root path.
    pub fn walk_dir<P: AsRef<UnixPath>>(&self, root: P) -> Result<WalkDir<'_, I>> {
        WalkDir::new(self, root)
    }

    /// Lists the immediate contents of a directory.
    ///
    /// This is equivalent to `walk_dir` with `max_depth(1)`.
    pub fn read_dir<P: AsRef<UnixPath>>(&self, path: P) -> Result<WalkDir<'_, I>> {
        Ok(WalkDir::new(self, path)?.max_depth(1))
    }

    /// Opens a file at the given path for reading.
    ///
    /// The returned [`File`] implements [`std::io::Read`].
    ///
    /// # Errors
    ///
    /// Returns an error if the path doesn't exist or is not a regular file.
    pub fn open<P: AsRef<UnixPath>>(&self, path: P) -> Result<File<'_, I>> {
        let inode = self
            .get_path_inode(&path)?
            .ok_or_else(|| Error::PathNotFound(path.as_ref().to_string_lossy().into_owned()))?;

        self.open_inode_file(inode)
    }

    /// Opens a file from an inode directly.
    ///
    /// This is useful when you already have an inode from directory traversal.
    pub fn open_inode_file(&self, inode: Inode) -> Result<File<'_, I>> {
        if !inode.is_file() {
            return Err(Error::NotAFile(format!(
                "inode {} is not a regular file",
                inode.id()
            )));
        }

        Ok(File::new(inode, self))
    }

    /// Returns a reference to the filesystem superblock.
    pub fn super_block(&self) -> &SuperBlock {
        &self.core.super_block
    }

    pub(crate) fn block_size(&self) -> usize {
        self.core.block_size
    }

    pub fn get_inode(&self, nid: u64) -> Result<Inode> {
        let offset = self.core.get_inode_offset(nid) as usize;
        let data = self
            .image
            .get(offset..)
            .ok_or_else(|| Error::OutOfBounds("failed to read inode format".to_string()))?;
        self.core.parse_inode(data, nid)
    }

    pub(crate) fn get_inode_block(&self, inode: &Inode, offset: usize) -> Result<&[u8]> {
        match self.core.plan_inode_block_read(inode, offset)? {
            BlockPlan::Direct { offset, size } => self
                .image
                .get(offset..offset + size)
                .ok_or_else(|| Error::OutOfBounds("failed to get inode data".to_string())),
            BlockPlan::Chunked {
                addr_offset,
                chunk_fixed,
                chunk_size,
                data_size,
                chunk_index,
            } => {
                let chunk_addr = self
                    .image
                    .get(addr_offset..addr_offset + 4)
                    .ok_or_else(|| Error::OutOfBounds("failed to get chunk address".to_string()))?
                    .get_i32_le();

                let (offset, size) = self.core.resolve_chunk_read(
                    chunk_addr,
                    chunk_fixed,
                    chunk_size,
                    data_size,
                    chunk_index,
                )?;
                self.image
                    .get(offset..offset + size)
                    .ok_or_else(|| Error::OutOfBounds("failed to get inode data".to_string()))
            }
        }
    }

    /// Looks up the inode at `path`, if it exists.
    pub fn lookup<P: AsRef<UnixPath>>(&self, path: P) -> Result<Option<Inode>> {
        self.get_path_inode(path)
    }

    /// Returns all extended attributes of `inode`: inline ones first, then
    /// shared ones (the order Linux `listxattr` uses).
    pub fn xattrs(&self, inode: &Inode) -> Result<Vec<Xattr>> {
        let mut out = Vec::new();
        let size = inode.xattr_size();
        if size == 0 {
            return Ok(out);
        }
        let off = self.core.xattr_ibody_offset(inode);
        let body = self
            .image
            .get(off..off + size)
            .ok_or_else(|| Error::OutOfBounds("failed to read xattr ibody".to_string()))?;
        let (shared, start) = xattr::parse_ibody(body)?;
        let long_prefixes = self.long_xattr_prefixes()?;

        xattr::parse_inline_entries(&body[start..], &long_prefixes, &mut out)?;
        for id in shared {
            let off = self.core.shared_xattr_offset(id)?;
            let data = self
                .image
                .get(off..)
                .ok_or_else(|| Error::OutOfBounds(format!("shared xattr {}", id)))?;
            let (h, suffix, value) = xattr::parse_entry(data)?;
            if let Some(name) = xattr::full_name(h.name_index, suffix, &long_prefixes)? {
                out.push(Xattr {
                    name,
                    value: value.to_vec(),
                });
            }
        }
        Ok(out)
    }

    /// Returns the value of the xattr called `name` (full name, e.g.
    /// `b"security.selinux"`), or `None` if the inode does not have it.
    pub fn get_xattr(&self, inode: &Inode, name: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .xattrs(inode)?
            .into_iter()
            .find(|x| x.name == name)
            .map(|x| x.value))
    }

    /// Reads the long xattr name prefix table (empty if the image has none).
    pub fn long_xattr_prefixes(&self) -> Result<Vec<LongPrefix>> {
        let Some(mut pos) = self.core.long_prefix_table_offset()? else {
            return Ok(Vec::new());
        };
        let count = self.core.super_block.xattr_prefix_count as usize;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            pos = xattr::align4(pos);
            let len = self
                .image
                .get(pos..pos + 2)
                .ok_or_else(|| Error::OutOfBounds("xattr prefix length".to_string()))?
                .get_u16_le() as usize;
            pos += 2;
            let payload = self
                .image
                .get(pos..pos + len)
                .ok_or_else(|| Error::OutOfBounds("xattr prefix data".to_string()))?;
            out.push(xattr::parse_long_prefix(payload)?);
            pos += len;
        }
        Ok(out)
    }

    pub(crate) fn get_path_inode<P: AsRef<UnixPath>>(&self, path: P) -> Result<Option<Inode>> {
        let mut nid = self.core.super_block.root_nid as u64;

        let path = path.as_ref().normalize();
        'outer: for part in path.components() {
            if part == UnixComponent::RootDir {
                continue;
            }

            let inode = self.get_inode(nid)?;
            let block_count = inode.data_size().div_ceil(self.core.block_size);
            if block_count == 0 {
                return Ok(None);
            }

            for i in 0..block_count {
                let block = self.get_inode_block(&inode, i * self.core.block_size)?;
                if let Some(found_nid) = dirent::find_nodeid_by_name(part.as_bytes(), block)? {
                    nid = found_nid;
                    continue 'outer;
                }
            }
            return Ok(None);
        }

        let inode = self.get_inode(nid)?;
        Ok(Some(inode))
    }
}
