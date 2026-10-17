"""Ký HMAC-SHA256 cho bảng baseline và whitelist trong CSDL.

Kẻ tấn công sửa thẳng file SQLite (đổi hash trong baseline cho khớp file đã bị sửa, hoặc thêm rule ignore '*'
để FIM "mù") sẽ làm chữ ký không còn khớp, vì không biết khóa. Khóa lấy từ biến môi trường FIM_HMAC_KEY,
hoặc file `integrity_key_file` (mặc định data/fim.key, tự sinh lần đầu, quyền 600 trên Linux).
Để an toàn hơn, đặt file khóa ở nơi khác thư mục CSDL hoặc dùng biến môi trường.
"""
from __future__ import annotations
import hashlib, hmac, json, os, secrets, time
from pathlib import Path

OK, TAMPERED, UNSIGNED, NO_KEY = 'OK', 'TAMPERED', 'UNSIGNED', 'NO_KEY'

# bảng -> câu SELECT theo thứ tự cố định (chữ ký không phụ thuộc thứ tự chèn dòng)
SIGNED_TABLES = {
    'baseline': 'SELECT path,sha256,size,mtime_ns,mode,uid,gid FROM baseline ORDER BY path',
    'whitelist': 'SELECT pattern,kind,events FROM whitelist ORDER BY kind,pattern',
}


class Signer:
    def __init__(self, key_file: str | None = None, env_key: str | None = None):
        self.key_file = Path(key_file) if key_file else None
        self._env_key = env_key

    @classmethod
    def from_cfg(cls, cfg) -> 'Signer':
        return cls(cfg.get('integrity_key_file'), os.environ.get('FIM_HMAC_KEY') or None)

    def key(self, create=False) -> bytes | None:
        """Khóa ký. Chỉ sinh khóa mới khi `create` (lúc ký); lúc kiểm tra mà mất khóa thì báo NO_KEY,
        không tự sinh lại - nếu không, xóa file khóa sẽ là cách vô hiệu hóa việc kiểm tra."""
        if self._env_key: return self._env_key.encode('utf-8')
        if not self.key_file: return None
        if not self.key_file.is_file():
            if not create: return None
            self.key_file.parent.mkdir(parents=True, exist_ok=True)
            # O_EXCL: monitor và dashboard (2 container) khởi động cùng lúc không được sinh ra 2 khóa khác nhau
            try:
                fd = os.open(self.key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'w', encoding='ascii') as f: f.write(secrets.token_hex(32))
            except FileExistsError: pass
        for _ in range(50):          # tiến trình kia có thể vừa tạo file nhưng chưa ghi xong
            k = self.key_file.read_text(encoding='ascii').strip()
            if k: return k.encode('ascii')
            time.sleep(0.02)
        raise RuntimeError(f'File khóa rỗng: {self.key_file}')

    @staticmethod
    def digest(conn, table: str, key: bytes) -> str:
        h = hmac.new(key, table.encode() + b'\n', hashlib.sha256)
        for row in conn.execute(SIGNED_TABLES[table]):
            h.update(json.dumps(list(row), ensure_ascii=False).encode('utf-8') + b'\n')
        return h.hexdigest()

    def sign(self, conn, table: str) -> str:
        return self.digest(conn, table, self.key(create=True))

    def verify(self, conn, table: str, stored: str | None) -> str:
        if not stored: return UNSIGNED
        try: key = self.key()
        except (OSError, RuntimeError): key = None
        if key is None: return NO_KEY
        return OK if hmac.compare_digest(stored, self.digest(conn, table, key)) else TAMPERED


DESCRIPTIONS = {
    TAMPERED: 'chữ ký không khớp - bảng đã bị sửa ngoài FIM',
    UNSIGNED: 'chưa có chữ ký (CSDL từ phiên bản cũ, hoặc chữ ký bị xóa)',
    NO_KEY: 'không tìm thấy khóa ký (FIM_HMAC_KEY / integrity_key_file)',
}
