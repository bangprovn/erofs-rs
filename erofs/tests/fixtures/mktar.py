import io, sys, tarfile
L = lambda c: {"SCHILY.xattr.security.selinux": f"u:object_r:{c}:s0"}
entries = [
    ("system", tarfile.DIRTYPE, b"", L("system_file")),
    ("system/bin", tarfile.DIRTYPE, b"", L("system_file")),
    ("system/bin/sh", tarfile.REGTYPE, b"hello\n", {**L("shell_exec"), "SCHILY.xattr.security.capability": "\x01\x00\x00\x02caps"}),
    ("system/bin/toybox", tarfile.SYMTYPE, b"sh", L("system_file")),
    ("system/etc", tarfile.DIRTYPE, b"", L("system_file")),
    ("system/etc/hosts", tarfile.REGTYPE, b"127.0.0.1 localhost\n", {**L("system_hosts_file"), "SCHILY.xattr.user.comment": "hosts"}),
    ("system/etc/plain", tarfile.REGTYPE, b"no xattrs\n", {}),
] + [(f"system/etc/f{i}", tarfile.REGTYPE, f"{i}\n".encode(), L("system_file")) for i in range(1, 5)]
with tarfile.open(sys.argv[1], "w", format=tarfile.PAX_FORMAT) as t:
    for name, typ, data, pax in entries:
        ti = tarfile.TarInfo(name); ti.type = typ; ti.mtime = 0; ti.uid = ti.gid = 0; ti.uname = ti.gname = "root"
        ti.mode = 0o755 if typ == tarfile.DIRTYPE else 0o644
        ti.pax_headers = pax
        if typ == tarfile.SYMTYPE: ti.linkname = data.decode(); t.addfile(ti)
        elif typ == tarfile.DIRTYPE: t.addfile(ti)
        else: ti.size = len(data); t.addfile(ti, io.BytesIO(data))
