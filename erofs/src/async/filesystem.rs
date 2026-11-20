use alloc::format;
use alloc::vec::Vec;
use typed_path::Component;

use bytes::Buf;
use typed_path::{UnixComponent, UnixPath};

use super::file::File;
use super::walkdir::WalkDir;
use crate::backend::AsyncImage;
use crate::dirent;
use crate::filesystem::{BlockPlan, EroFSCore};
use crate::types::*;
use crate::xattr::{self, LongPrefix, Xattr};
use crate::{Error, Result};

/// The async entry point for reading EROFS filesystem images.
///
/// `EroFS` provides async methods to traverse directories, open files, and access
/// filesystem metadata from EROFS images.
#[derive(Debug, Clone)]
pub struct EroFS<I: AsyncImage> {
    image: I,
    core: EroFSCore,
}

impl<I: AsyncImage> EroFS<I> {
    /// Creates a new async `EroFS` instance from an async backend image source.
    pub async fn new(image: I) -> Result<Self> {
        let mut super_block = vec![0u8; SuperBlock::size()];
        image
            .read_exact_at(&mut super_block, SUPER_BLOCK_OFFSET)
            .await?;
        let core = EroFSCore::new(&super_block)?;
        Ok(Self { image, core })
    }

    /// Recursively walks a directory tree starting from the given path.
    pub async fn walk_dir(&self, root: impl AsRef<UnixPath>) -> Result<WalkDir<'_, I>> {
        WalkDir::new(self, root.as_ref()).await
    }

    /// Lists the immediate contents of a directory.
    pub async fn read_dir(&self, path: impl AsRef<UnixPath>) -> Result<WalkDir<'_, I>> {
        Ok(WalkDir::new(self, path.as_ref()).await?.max_depth(1))
    }

    /// Opens a file at the given path for reading.
    ///
    /// The returned [`File`] provides an async [`read`](File::read) method.
    ///
    /// # Errors
    ///
    /// Returns an error if the path doesn't exist or is not a regular file.
    pub async fn open(&self, path: impl AsRef<UnixPath>) -> Result<File<'_, I>> {
        let inode = self
            .get_path_inode(path.as_ref())
            .await?
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

    pub async fn get_inode(&self, nid: u64) -> Result<Inode> {
        let offset = self.core.get_inode_offset(nid) as usize;
        let mut buf = vec![0u8; InodeExtended::size()];
        self.image.read_exact_at(&mut buf, offset).await?;
        self.core.parse_inode(&buf, nid)
    }

    pub(crate) async fn read_inode_block(&self, inode: &Inode, offset: usize) -> Result<Vec<u8>> {
        match self.core.plan_inode_block_read(inode, offset)? {
            BlockPlan::Direct { offset, size } => {
                if size > self.core.block_size {
                    return Err(Error::CorruptedData(format!(
                        "invalid direct block size {} at offset {}",
                        size, offset
                    )));
                }

                let mut buf = vec![0u8; size];
                self.image.read_exact_at(&mut buf, offset).await?;
                Ok(buf)
            }
            BlockPlan::Chunked {
                addr_offset,
                chunk_fixed,
                chunk_size,
                data_size,
                chunk_index,
            } => {
                let mut addr_buf = vec![0u8; 4];
                self.image.read_exact_at(&mut addr_buf, addr_offset).await?;
                let chunk_addr = (&addr_buf[..]).get_i32_le();

                let (offset, size) = self.core.resolve_chunk_read(
                    chunk_addr,
                    chunk_fixed,
                    chunk_size,
                    data_size,
                    chunk_index,
                )?;
                let mut buf = vec![0u8; size];
                self.image.read_exact_at(&mut buf, offset).await?;
                Ok(buf)
            }
        }
    }

    /// Looks up the inode at `path`, if it exists.
    pub async fn lookup(&self, path: impl AsRef<UnixPath>) -> Result<Option<Inode>> {
        self.get_path_inode(path.as_ref()).await
    }

    async fn read_at(&self, offset: usize, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.image.read_exact_at(&mut buf, offset).await?;
        Ok(buf)
    }

    /// Returns all extended attributes of `inode`: inline ones first, then
    /// shared ones. See [`crate::EroFS::xattrs`].
    pub async fn xattrs(&self, inode: &Inode) -> Result<Vec<Xattr>> {
        let mut out = Vec::new();
        let size = inode.xattr_size();
        if size == 0 {
            return Ok(out);
        }
        let body = self
            .read_at(self.core.xattr_ibody_offset(inode), size)
            .await?;
        let (shared, start) = xattr::parse_ibody(&body)?;
        let long_prefixes = self.long_xattr_prefixes().await?;

        xattr::parse_inline_entries(&body[start..], &long_prefixes, &mut out)?;
        for id in shared {
            let off = self.core.shared_xattr_offset(id)?;
            let head = self.read_at(off, xattr::XATTR_ENTRY_SIZE).await?;
            let h = xattr::EntryHeader::parse(&head)?;
            let data = self.read_at(off, h.body_len()).await?;
            let (h, suffix, value) = xattr::parse_entry(&data)?;
            if let Some(name) = xattr::full_name(h.name_index, suffix, &long_prefixes)? {
                out.push(Xattr {
                    name,
                    value: value.to_vec(),
                });
            }
        }
        Ok(out)
    }

    /// Returns the value of the xattr called `name`, or `None`.
    pub async fn get_xattr(&self, inode: &Inode, name: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .xattrs(inode)
            .await?
            .into_iter()
            .find(|x| x.name == name)
            .map(|x| x.value))
    }

    /// Reads the long xattr name prefix table (empty if the image has none).
    pub async fn long_xattr_prefixes(&self) -> Result<Vec<LongPrefix>> {
        let Some(mut pos) = self.core.long_prefix_table_offset()? else {
            return Ok(Vec::new());
        };
        let count = self.core.super_block.xattr_prefix_count as usize;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            pos = xattr::align4(pos);
            let len = (&self.read_at(pos, 2).await?[..]).get_u16_le() as usize;
            pos += 2;
            let payload = self.read_at(pos, len).await?;
            out.push(xattr::parse_long_prefix(&payload)?);
            pos += len;
        }
        Ok(out)
    }

    pub(crate) async fn get_path_inode(&self, path: &UnixPath) -> Result<Option<Inode>> {
        let mut nid = self.core.super_block.root_nid as u64;

        let path = path.normalize();
        'outer: for part in path.components() {
            if part == UnixComponent::RootDir {
                continue;
            }

            let inode = self.get_inode(nid).await?;
            let block_count = inode.data_size().div_ceil(self.core.block_size);
            if block_count == 0 {
                return Ok(None);
            }

            for i in 0..block_count {
                let block = self
                    .read_inode_block(&inode, i * self.core.block_size)
                    .await?;
                if let Some(found_nid) = dirent::find_nodeid_by_name(part.as_bytes(), &block)? {
                    nid = found_nid;
                    continue 'outer;
                }
            }
            return Ok(None);
        }

        let inode = self.get_inode(nid).await?;
        Ok(Some(inode))
    }
}
