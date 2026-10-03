"""Baseline hash & so sánh trạng thái file."""
from __future__ import annotations
import fnmatch, hashlib, os, stat
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FileState:
    path: str
    sha256: str
    size: int
    mtime_ns: int
    mode: int


@dataclass
class Change:
    path: str
    event_type: str          # CREATED / MODIFIED / DELETED / MOVED / PERMISSION_CHANGED (có thể ghép bằng '+')
    old: FileState | None
    new: FileState | None


def sha256_file(path: Path, chunk_size=1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        while True:
            b = f.read(chunk_size)
            if not b: break
            h.update(b)
    return h.hexdigest()


def matches(patterns, *candidates) -> bool:
    """True nếu một trong các chuỗi (đường dẫn tuyệt đối, tương đối, tên file) khớp một pattern."""
    return any(fnmatch.fnmatch(c, x) for x in patterns for c in candidates if c)


def rel_path(key: str, roots: list[str]) -> str:
    """Đường dẫn tương đối so với thư mục giám sát chứa file (root dài nhất khớp)."""
    best = ''
    for r in roots:
        r = r.rstrip('/')
        if key.startswith(r + '/') and len(r) > len(best): best = r
    return key[len(best) + 1:] if best else key


def is_ignored(key: str, roots: list[str], ignore: list[str]) -> bool:
    return matches(ignore, key, rel_path(key, roots), key.rsplit('/', 1)[-1])


def scan_tree(roots: list[str], ignore=(), prev: dict[str, FileState] | None = None):
    """Quét các thư mục giám sát, trả về (states, errors).

    Nếu truyền `prev` (quick scan), file có size + mtime không đổi sẽ dùng lại hash cũ
    thay vì đọc lại toàn bộ nội dung. Full scan (prev=None) luôn hash lại mọi file.
    """
    ignore = list(ignore); states: dict[str, FileState] = {}; errors: list[str] = []
    for root in roots:
        rootp = Path(root)
        if not rootp.is_dir():
            errors.append(f'{root}: thư mục không tồn tại'); continue
        for dirpath, dirnames, filenames in os.walk(rootp, onerror=lambda e: errors.append(f'{e.filename}: {e.strerror}')):
            cur = Path(dirpath)
            dirnames[:] = [d for d in dirnames
                           if not matches(ignore, (cur / d).relative_to(rootp).as_posix() + '/', d + '/')]
            for name in filenames:
                p = cur / name; key = p.as_posix(); rel = p.relative_to(rootp).as_posix()
                if matches(ignore, key, rel, name): continue
                try:
                    st = p.stat()
                    if not stat.S_ISREG(st.st_mode): continue   # bỏ qua socket, FIFO, device...
                    old = prev.get(key) if prev else None
                    if old and old.size == st.st_size and old.mtime_ns == st.st_mtime_ns:
                        digest = old.sha256
                    else:
                        digest = sha256_file(p)
                    states[key] = FileState(key, digest, st.st_size, st.st_mtime_ns, st.st_mode & 0o7777)
                except OSError as e:
                    errors.append(f'{key}: {e.strerror or e}')
    return states, errors


def compare_states(old: dict[str, FileState], new: dict[str, FileState]) -> list[Change]:
    out = []; a = set(old); b = set(new)
    created = sorted(b - a); deleted = sorted(a - b)
    # File bị xóa + file mới có cùng nội dung => đổi tên / di chuyển
    by_hash: dict[str, list[str]] = {}
    for p in deleted:
        if old[p].size > 0: by_hash.setdefault(old[p].sha256, []).append(p)
    moved_from = set()
    for p in created:
        src = by_hash.get(new[p].sha256)
        if src:
            q = src.pop(0); moved_from.add(q); out.append(Change(p, 'MOVED', old[q], new[p]))
        else:
            out.append(Change(p, 'CREATED', None, new[p]))
    for p in deleted:
        if p not in moved_from: out.append(Change(p, 'DELETED', old[p], None))
    for p in sorted(a & b):
        o, n = old[p], new[p]
        content = (o.sha256 != n.sha256 or o.size != n.size)
        perm = (o.mode != n.mode)
        if content and perm: typ = 'MODIFIED+PERMISSION_CHANGED'
        elif content: typ = 'MODIFIED'
        elif perm: typ = 'PERMISSION_CHANGED'
        else: continue
        out.append(Change(p, typ, o, n))
    return out
