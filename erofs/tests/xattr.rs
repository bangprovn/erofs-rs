//! Extended attribute tests.
//!
//! Real images built by erofs-utils (see `tests/fixtures/README.md`) cover
//! inline and long-prefix xattrs; a hand-built image covers shared xattrs.

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use erofs_rs::r#async::EroFS as AsyncEroFS;
use erofs_rs::backend::{AsyncImage, SliceImage};
use erofs_rs::xattr::LongPrefix;
use erofs_rs::{EroFS, Result, Xattr};

const INLINE: &[u8] = include_bytes!("fixtures/xattr-inline.erofs");
const LONG_PREFIX: &[u8] = include_bytes!("fixtures/xattr-long-prefix.erofs");

fn label(t: &str) -> Vec<u8> {
    format!("u:object_r:{t}:s0").into_bytes()
}

fn x(name: &str, value: &[u8]) -> Xattr {
    Xattr {
        name: name.as_bytes().to_vec(),
        value: value.to_vec(),
    }
}

/// The xattrs `fixtures/mktar.py` puts on each path.
fn expected(path: &str) -> Vec<Xattr> {
    let sel = |t| x("security.selinux", &label(t));
    match path {
        "/system" | "/system/bin" | "/system/etc" | "/system/bin/toybox" => {
            vec![sel("system_file")]
        }
        "/system/bin/sh" => vec![
            sel("shell_exec"),
            x("security.capability", b"\x01\x00\x00\x02caps"),
        ],
        "/system/etc/hosts" => vec![sel("system_hosts_file"), x("user.comment", b"hosts")],
        "/system/etc/plain" | "/" => vec![],
        p if p.starts_with("/system/etc/f") => vec![sel("system_file")],
        p => panic!("no expectation for {p}"),
    }
}

const PATHS: &[&str] = &[
    "/",
    "/system",
    "/system/bin",
    "/system/bin/sh",
    "/system/bin/toybox",
    "/system/etc",
    "/system/etc/hosts",
    "/system/etc/plain",
    "/system/etc/f1",
    "/system/etc/f4",
];

fn check_image(data: &[u8]) {
    let fs = EroFS::new(SliceImage::new(data)).unwrap();
    for p in PATHS {
        let inode = fs
            .lookup(p)
            .unwrap()
            .unwrap_or_else(|| panic!("{p} missing"));
        assert_eq!(fs.xattrs(&inode).unwrap(), expected(p), "xattrs of {p}");
    }
    let sh = fs.lookup("/system/bin/sh").unwrap().unwrap();
    assert_eq!(
        fs.get_xattr(&sh, b"security.selinux").unwrap(),
        Some(label("shell_exec"))
    );
    assert_eq!(fs.get_xattr(&sh, b"user.missing").unwrap(), None);
}

#[test]
fn inline_xattrs_from_mkfs_erofs() {
    check_image(INLINE);
    let fs = EroFS::new(SliceImage::new(INLINE)).unwrap();
    assert!(fs.long_xattr_prefixes().unwrap().is_empty());
}

#[test]
fn long_prefix_xattrs_from_mkfs_erofs() {
    check_image(LONG_PREFIX);
    let fs = EroFS::new(SliceImage::new(LONG_PREFIX)).unwrap();
    assert_eq!(
        fs.long_xattr_prefixes().unwrap(),
        vec![LongPrefix {
            base_index: 6,
            infix: b"sel".to_vec()
        }]
    );
}

// ---- hand-built image with shared xattrs ----

fn put(buf: &mut [u8], off: usize, bytes: &[u8]) {
    buf[off..off + bytes.len()].copy_from_slice(bytes);
}

fn entry(index: u8, name: &[u8], value: &[u8]) -> Vec<u8> {
    let mut v = vec![name.len() as u8, index];
    v.extend_from_slice(&(value.len() as u16).to_le_bytes());
    v.extend_from_slice(name);
    v.extend_from_slice(value);
    v.resize(v.len().div_ceil(4) * 4, 0);
    v
}

/// 3 x 4 KiB blocks: superblock in block 0, one compact inode (nid 0) in
/// the meta block 1, shared xattrs in block 2.
fn shared_image() -> Vec<u8> {
    const BS: usize = 4096;
    let mut img = vec![0u8; 3 * BS];
    let sb = 1024;
    put(&mut img, sb, &0xe0f5_e1e2u32.to_le_bytes()); // magic
    img[sb + 12] = 12; // blk_size_bits
    put(&mut img, sb + 40, &1u32.to_le_bytes()); // meta_blk_addr
    put(&mut img, sb + 44, &2u32.to_le_bytes()); // xattr_blk_addr

    // shared area: id 0 = security.selinux (36 bytes -> next id 9), id 9 = trusted.x
    let a = entry(6, b"selinux", &label("system_file"));
    assert_eq!(a.len(), 36);
    let b = entry(4, b"x", b"1");
    put(&mut img, 2 * BS, &a);
    put(&mut img, 2 * BS + a.len(), &b);

    // inline ibody: header(12) + 2 shared ids(8) + user.k=v (8) = 28 bytes
    let mut body = vec![0u8; 12];
    body[4] = 2;
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&((a.len() / 4) as u32).to_le_bytes());
    body.extend(entry(1, b"k", b"v"));
    assert_eq!(body.len(), 28);
    let icount = ((body.len() - 12) / 4 + 1) as u16;

    let ino = BS; // nid 0
    put(&mut img, ino, &0u16.to_le_bytes()); // compact, FlatPlain
    put(&mut img, ino + 2, &icount.to_le_bytes());
    put(&mut img, ino + 4, &0o100644u16.to_le_bytes());
    put(&mut img, ino + 6, &1u16.to_le_bytes());
    put(&mut img, ino + 32, &body);
    img
}

fn shared_expected() -> Vec<Xattr> {
    vec![
        x("user.k", b"v"),
        x("security.selinux", &label("system_file")),
        x("trusted.x", b"1"),
    ]
}

#[test]
fn shared_xattrs_follow_inline_ones() {
    let img = shared_image();
    let fs = EroFS::new(SliceImage::new(&img)).unwrap();
    let inode = fs.get_inode(0).unwrap();
    assert_eq!(inode.xattr_size(), 28);
    assert_eq!(fs.xattrs(&inode).unwrap(), shared_expected());
    assert_eq!(
        fs.get_xattr(&inode, b"trusted.x").unwrap(),
        Some(b"1".to_vec())
    );
}

#[test]
fn shared_id_past_end_of_image_is_an_error() {
    let mut img = shared_image();
    put(&mut img, 4096 + 32 + 12, &0x00ff_ffffu32.to_le_bytes());
    let fs = EroFS::new(SliceImage::new(&img)).unwrap();
    let inode = fs.get_inode(0).unwrap();
    assert!(fs.xattrs(&inode).is_err());
}

// ---- async API ----

struct VecImage(Vec<u8>);

impl AsyncImage for VecImage {
    async fn read_exact_at(&self, buf: &mut [u8], offset: usize) -> Result<usize> {
        let src = self
            .0
            .get(offset..offset + buf.len())
            .ok_or_else(|| erofs_rs::Error::OutOfBounds(format!("{offset}+{}", buf.len())))?;
        buf.copy_from_slice(src);
        Ok(buf.len())
    }
}

/// The in-memory image never pends, so polling once is enough.
fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("in-memory future pended"),
    }
}

#[test]
fn async_api_matches_sync() {
    for data in [INLINE, LONG_PREFIX] {
        let fs = block_on(AsyncEroFS::new(VecImage(data.to_vec()))).unwrap();
        for p in PATHS {
            let inode = block_on(fs.lookup(p)).unwrap().unwrap();
            assert_eq!(
                block_on(fs.xattrs(&inode)).unwrap(),
                expected(p),
                "async {p}"
            );
        }
    }
    let fs = block_on(AsyncEroFS::new(VecImage(shared_image()))).unwrap();
    let inode = block_on(fs.get_inode(0)).unwrap();
    assert_eq!(block_on(fs.xattrs(&inode)).unwrap(), shared_expected());
    assert_eq!(
        block_on(fs.get_xattr(&inode, b"security.selinux")).unwrap(),
        Some(label("system_file"))
    );
}
