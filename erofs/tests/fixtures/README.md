# xattr test fixtures

Built with erofs-utils `mkfs.erofs` 1.9 (tar mode; only upstream options used) from a tar whose
members carry PAX `SCHILY.xattr.*` records, so the xattrs are exactly the
ones listed in `mktar.py` (no host metadata):

```sh
python3 mktar.py src.tar
mkfs.erofs --tar=f -U 00000000-0000-0000-0000-000000000000 -T0 -x100 \
    xattr-inline.erofs src.tar
mkfs.erofs --tar=f -U 00000000-0000-0000-0000-000000000000 -T0 -x1 \
    --xattr-prefix=security.sel xattr-long-prefix.erofs src.tar
```

- `xattr-inline.erofs`: every xattr stored inline after its inode.
- `xattr-long-prefix.erofs`: same tree, with the `xattr_prefixes` feature
  and one long prefix (`security.` + `sel`), so `security.selinux` entries
  are stored as long-prefix index 0 with suffix `inux`.

Tar mode never emits shared xattrs, so `tests/xattr.rs` covers those with a
small hand-built image.
