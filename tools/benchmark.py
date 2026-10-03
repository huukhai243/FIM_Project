"""Kịch bản kiểm thử & đo đạc FIM.

Đo 3 chỉ số và ghi kết quả ra docs/benchmark_results.md:
  1. Hiệu năng quét baseline (full hash) và quick scan, theo số lượng / dung lượng file
  2. Độ trễ phát hiện: từ lúc sửa file đến lúc sự kiện có trong DB (watchdog/inotify vs polling)
  3. Độ chính xác phân loại trên bộ kịch bản hợp lệ / tấn công (confusion matrix)

Chạy:  python tools/benchmark.py            (đầy đủ, ~2-3 phút)
       python tools/benchmark.py --quick    (nhanh, ~30 giây)
"""
from __future__ import annotations
import argparse, contextlib, io, json, logging, os, platform, random, shutil, sqlite3, statistics, subprocess, sys, tempfile, time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from fim import service, __version__            # noqa: E402
from fim.core import scan_tree                   # noqa: E402


def quiet(fn, *args, **kw):
    """Gọi hàm của service mà không in log ra màn hình."""
    with contextlib.redirect_stderr(io.StringIO()):
        try: return fn(*args, **kw)
        finally: close_logs()


def close_logs():
    for h in logging.getLogger('fim').handlers: h.close()
    logging.getLogger('fim').handlers.clear()


def version_of(mod):
    try:
        from importlib.metadata import version
        return version(mod)
    except Exception:
        return '-'


def env_info():
    return {
        'Thời điểm đo': datetime.now().strftime('%Y-%m-%d %H:%M'),
        'Hệ điều hành': platform.platform(),
        'CPU': f'{platform.processor() or platform.machine()} ({os.cpu_count()} luồng)',
        'Python': platform.python_version(),
        'SQLite': sqlite3.sqlite_version,
        'watchdog': version_of('watchdog'),
        'Flask': version_of('flask'),
        'FIM': __version__,
    }


# ---------------------------------------------------------------- 1. hiệu năng quét
def bench_scan(cases):
    rows = []
    for n, size in cases:
        tmp = Path(tempfile.mkdtemp(prefix='fimbench_'))
        try:
            for i in range(n):
                d = tmp / f'd{i // 100:03d}'
                if i % 100 == 0: d.mkdir()
                (d / f'f{i:05d}.bin').write_bytes(os.urandom(size))
            t = time.perf_counter(); states, _ = scan_tree([tmp.as_posix()]); full = time.perf_counter() - t
            t = time.perf_counter(); scan_tree([tmp.as_posix()], prev=states); quick = time.perf_counter() - t
            mb = n * size / 1024 / 1024
            rows.append({'files': n, 'size': size, 'mb': mb, 'full': full, 'quick': quick,
                         'fps': n / full, 'mbps': mb / full})
            print(f'  scan {n:>6} x {size // 1024:>5} KB: full {full:.3f}s  quick {quick:.3f}s')
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    return rows


# ---------------------------------------------------------------- 2. độ trễ phát hiện
def make_env(tmp: Path, extra=None):
    w = tmp / 'w'
    for p, content in {'etc/app.conf': 'port=80\n', 'bin/tool.sh': '#!/bin/sh\necho hi\n',
                       'var/log/app.log': 'boot ok\n', 'home/user/notes.txt': 'hello\n'}.items():
        f = w / p; f.parent.mkdir(parents=True, exist_ok=True); f.write_text(content)
    cfg = {
        'watch_paths': [{'path': (w / 'etc').as_posix(), 'label': 'etc', 'critical': True},
                        {'path': (w / 'bin').as_posix(), 'label': 'bin', 'critical': True},
                        {'path': (w / 'var/log').as_posix(), 'label': 'log'},
                        {'path': (w / 'home').as_posix(), 'label': 'home'}],
        'database': (tmp / 'fim.db').as_posix(), 'log_file': (tmp / 'fim.log').as_posix(),
        'whitelist': ['*.tmp', '*.swp'],
        'allowed_changes': [{'pattern': '*.log', 'events': 'CREATED,MODIFIED'}],
        'sensitive_paths': ['*.conf', '*.sh'], 'executable_extensions': ['.sh'],
        'suspicious_threshold': 3, 'mass_change_threshold': 10,
        'work_hours': [0, 24],          # loại bỏ yếu tố thời gian để kết quả lặp lại được
        'debounce_seconds': 0.5, 'poll_interval_seconds': 1.0, 'full_scan_interval_seconds': 3600,
    }
    cfg.update(extra or {})
    cfgp = tmp / 'config.json'; cfgp.write_text(json.dumps(cfg))
    return w, cfgp


def bench_latency(mode, trials):
    tmp = Path(tempfile.mkdtemp(prefix='fimlat_'))
    proc = None
    try:
        w, cfgp = make_env(tmp, {'force_polling': mode == 'polling'})
        quiet(service.initialize, str(cfgp))
        proc = subprocess.Popen([sys.executable, str(ROOT / 'main.py'), '--config', str(cfgp), 'monitor'],
                                cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log = tmp / 'fim.log'; deadline = time.time() + 15
        while time.time() < deadline and not (log.exists() and ('Monitoring' in log.read_text('utf-8') or 'polling' in log.read_text('utf-8'))):
            time.sleep(0.1)
        time.sleep(1.5)                                   # chờ lần quét khởi động
        conn = sqlite3.connect(tmp / 'fim.db', timeout=10)
        last = lambda: conn.execute('SELECT COALESCE(MAX(id),0) FROM events').fetchone()[0]
        lat = []
        for i in range(trials):
            before = last(); t0 = time.perf_counter()
            with open(w / 'etc/app.conf', 'a') as f: f.write(f'k{i}=v\n')
            while time.perf_counter() - t0 < 10:
                if last() > before: lat.append(time.perf_counter() - t0); break
                time.sleep(0.01)
            time.sleep(random.uniform(0.6, 1.6))      # khoảng nghỉ ngẫu nhiên: tránh trùng pha với chu kỳ polling
        conn.close()
        print(f'  latency {mode:<8}: n={len(lat)}/{trials} avg {statistics.mean(lat):.3f}s' if lat else f'  latency {mode}: no events')
        return lat, trials
    finally:
        if proc:
            proc.terminate()
            try: proc.wait(10)
            except subprocess.TimeoutExpired: proc.kill()
        time.sleep(0.5); shutil.rmtree(tmp, ignore_errors=True)


def pct(xs, p):
    xs = sorted(xs); k = (len(xs) - 1) * p / 100; f = int(k)
    return xs[f] + (xs[min(f + 1, len(xs) - 1)] - xs[f]) * (k - f)


# ---------------------------------------------------------------- 3. độ chính xác phân loại
def _mass(w):
    for i in range(12): (w / f'home/user/doc{i}.txt.enc').write_text('x')


SCENARIOS = [
    # (mô tả, hành động, (loại sự kiện, kết luận) mong đợi hoặc None = không được có sự kiện, chỉ Linux)
    ('Tạo ghi chú mới trong home',             lambda w: (w / 'home/user/todo.txt').write_text('a'),            ('CREATED', 'LEGITIMATE'), False),
    ('Sửa ghi chú trong home',                 lambda w: (w / 'home/user/notes.txt').write_text('edited'),      ('MODIFIED', 'LEGITIMATE'), False),
    ('Ứng dụng ghi thêm log',                  lambda w: open(w / 'var/log/app.log', 'a').write('more\n'),      ('MODIFIED', 'LEGITIMATE'), False),
    ('Tạo file log mới (log rotation)',        lambda w: (w / 'var/log/app2.log').write_text('new'),           ('CREATED', 'LEGITIMATE'), False),
    ('Tạo file tạm *.tmp (whitelist ignore)',  lambda w: (w / 'home/user/x.tmp').write_text('t'),               None, False),
    ('Chỉ đổi mtime, nội dung giữ nguyên',     lambda w: os.utime(w / 'etc/app.conf', (1, 1)),                  None, False),
    ('Sửa file cấu hình trong etc',            lambda w: open(w / 'etc/app.conf', 'a').write('PermitRootLogin yes\n'), ('MODIFIED', 'SUSPICIOUS'), False),
    ('Tạo file cấu hình mới trong etc',        lambda w: (w / 'etc/evil.conf').write_text('x'),                 ('CREATED', 'SUSPICIOUS'), False),
    ('Thay thế chương trình trong bin',        lambda w: (w / 'bin/tool.sh').write_text('#!/bin/sh\nrm -rf /\n'), ('MODIFIED', 'SUSPICIOUS'), False),
    ('Xóa chương trình trong bin',             lambda w: (w / 'bin/tool.sh').unlink(),                          ('DELETED', 'SUSPICIOUS'), False),
    ('Tạo file ẩn (backdoor) trong home',      lambda w: (w / 'home/user/.backdoor').write_text('nc'),          ('CREATED', 'SUSPICIOUS'), False),
    ('Đổi tên file sang .locked (ransomware)', lambda w: (w / 'home/user/notes.txt').rename(w / 'home/user/notes.txt.locked'), ('MOVED', 'SUSPICIOUS'), False),
    ('Tạo 12 file .enc cùng lúc',              _mass,                                                          ('CREATED', 'SUSPICIOUS'), False),
    ('Xóa file log (xóa dấu vết)',             lambda w: (w / 'var/log/app.log').unlink(),                      ('DELETED', 'SUSPICIOUS'), False),
    ('Làm rỗng file log (xóa dấu vết)',        lambda w: (w / 'var/log/app.log').write_text(''),                ('MODIFIED', 'SUSPICIOUS'), False),
    ('chmod 600 ghi chú (thu hẹp quyền)',      lambda w: os.chmod(w / 'home/user/notes.txt', 0o600),            ('PERMISSION_CHANGED', 'LEGITIMATE'), True),
    ('chmod +x file trong home',               lambda w: os.chmod(w / 'home/user/notes.txt', 0o755),            ('PERMISSION_CHANGED', 'SUSPICIOUS'), True),
    ('chmod u+s script trong bin (setuid)',    lambda w: os.chmod(w / 'bin/tool.sh', 0o4755),                   ('PERMISSION_CHANGED', 'SUSPICIOUS'), True),
]


def bench_accuracy():
    rows = []
    for name, act, expected, posix_only in SCENARIOS:
        if posix_only and os.name != 'posix':
            rows.append({'name': name, 'expected': expected, 'got': None, 'ok': None}); continue
        tmp = Path(tempfile.mkdtemp(prefix='fimacc_'))
        try:
            w, cfgp = make_env(tmp)
            if posix_only:
                for f in w.rglob('*'):
                    if f.is_file(): os.chmod(f, 0o644)
            quiet(service.initialize, str(cfgp))
            act(w)
            _, results, _ = quiet(service.scan_baseline, str(cfgp))
            got = sorted({(c.event_type, v.verdict) for c, v in results})
            if expected is None: ok = not results
            else: ok = bool(results) and all(t == expected for t in got)
            rows.append({'name': name, 'expected': expected, 'got': got, 'ok': ok,
                         'scores': sorted({v.score for _, v in results})})
        finally:
            close_logs(); shutil.rmtree(tmp, ignore_errors=True)
        print(f"  {'PASS' if rows[-1]['ok'] else 'FAIL'}  {name}")
    return rows


# ---------------------------------------------------------------- báo cáo
def report(env, scan, lat, acc, out: Path):
    L = ['# Kết quả kiểm thử & đo đạc FIM', '', '## Môi trường đo', '', '| Thông số | Giá trị |', '|---|---|']
    L += [f'| {k} | {v} |' for k, v in env.items()]

    L += ['', '## 1. Hiệu năng quét', '',
          'Full scan = đọc và tính SHA-256 toàn bộ file (dùng cho `init`, `scan`, `accept`). '
          'Quick scan = chỉ hash lại file có size/mtime thay đổi (dùng khi `monitor` nhận sự kiện). '
          'Đo khi file đã nằm trong page cache của hệ điều hành. Với file nhỏ, chi phí mở file chiếm phần lớn '
          '(trên Windows còn bị phần mềm diệt virus quét khi mở file), nên tốc độ tính theo file/s quan trọng hơn MB/s.', '',
          '| Số file | Kích thước/file | Tổng dung lượng | Full scan (s) | Tốc độ (file/s) | Thông lượng (MB/s) | Quick scan (s) | Quick nhanh hơn |',
          '|---:|---:|---:|---:|---:|---:|---:|---:|']
    for r in scan:
        size = f"{r['size'] // 1024} KB" if r['size'] < 1024 * 1024 else f"{r['size'] // 1024 // 1024} MB"
        L.append(f"| {r['files']:,} | {size} | {r['mb']:.1f} MB | {r['full']:.3f} | {r['fps']:,.0f} | {r['mbps']:.1f} | "
                 f"{r['quick']:.3f} | {r['full'] / max(r['quick'], 1e-9):.1f}x |")

    L += ['', '## 2. Độ trễ phát hiện', '',
          'Từ lúc ghi vào `etc/app.conf` đến lúc sự kiện xuất hiện trong bảng `events`. '
          '`debounce_seconds = 0.5`, `poll_interval_seconds = 1.0`.', '',
          '| Cơ chế | Số lần đo | Phát hiện | Min (s) | Trung bình (s) | Trung vị (s) | P95 (s) | Max (s) |',
          '|---|---:|---:|---:|---:|---:|---:|---:|']
    for mode, (xs, n) in lat.items():
        if xs:
            L.append(f'| {mode} | {n} | {len(xs)}/{n} | {min(xs):.3f} | {statistics.mean(xs):.3f} | '
                     f'{statistics.median(xs):.3f} | {pct(xs, 95):.3f} | {max(xs):.3f} |')
        else:
            L.append(f'| {mode} | {n} | 0/{n} | - | - | - | - | - |')

    L += ['', 'Watchdog: sự kiện đến gần như tức thời, độ trễ chủ yếu do `debounce` (chờ 0.5 s không có sự kiện mới) '
          '+ chu kỳ vòng lặp 0.2 s. Polling: trung bình nửa chu kỳ quét + thời gian quét.', '',
          '**Chi phí khi không có thay đổi** (ước tính từ thời gian quick scan ở mục 1, polling mỗi 1 s):', '',
          '| Số file giám sát | Polling: thời gian quét mỗi chu kỳ | Tỉ lệ thời gian bận (ước tính) | Watchdog |', '|---:|---:|---:|---|']
    for r in scan:
        if r['size'] <= 64 * 1024:
            L.append(f"| {r['files']:,} | {r['quick']:.3f} s | {r['quick'] / 1.0:.0%} | ≈ 0 (chỉ quét khi có sự kiện) |")
    L += ['', '## 3. Độ chính xác phân loại', '',
          'Mỗi kịch bản chạy trên môi trường sạch: tạo baseline → thực hiện hành động → `scan`. '
          '`work_hours = [0, 24]` để loại yếu tố giờ làm việc.', '',
          '| # | Kịch bản | Mong đợi | Thực tế | Điểm | Kết quả |', '|---:|---|---|---|---:|:---:|']
    for i, r in enumerate(acc, 1):
        exp = 'không có sự kiện' if r['expected'] is None else f"{r['expected'][0]} / {r['expected'][1]}"
        if r['ok'] is None:
            L.append(f"| {i} | {r['name']} | {exp} | *chỉ chạy trên Linux* | - | N/A |"); continue
        got = ', '.join(f'{t} / {v}' for t, v in r['got']) or 'không có sự kiện'
        L.append(f"| {i} | {r['name']} | {exp} | {got} | {', '.join(map(str, r['scores'])) or '-'} | {'✅' if r['ok'] else '❌'} |")

    ran = [r for r in acc if r['ok'] is not None]
    attack = lambda r: r['expected'] is not None and r['expected'][1] == 'SUSPICIOUS'
    flagged = lambda r: any(v == 'SUSPICIOUS' for _, v in (r['got'] or []))
    tp = sum(attack(r) and flagged(r) for r in ran); fn = sum(attack(r) and not flagged(r) for r in ran)
    fp = sum(not attack(r) and flagged(r) for r in ran); tn = sum(not attack(r) and not flagged(r) for r in ran)
    prec = tp / (tp + fp) if tp + fp else 0; rec = tp / (tp + fn) if tp + fn else 0
    skipped = len(acc) - len(ran)
    L += ['', f'**Ma trận nhầm lẫn** ({len(ran)} kịch bản đã chạy' + (f', bỏ qua {skipped} kịch bản chỉ chạy được trên Linux' if skipped else '') + '):', '',
          '| | Hệ thống báo SUSPICIOUS | Hệ thống báo LEGITIMATE / không báo |', '|---|---:|---:|',
          f'| **Thực tế là tấn công** | TP = {tp} | FN = {fn} |', f'| **Thực tế là hợp lệ** | FP = {fp} | TN = {tn} |', '',
          f'- Accuracy = {(tp + tn) / len(ran):.0%}  ·  Precision = {prec:.0%}  ·  Recall = {rec:.0%}',
          f'- Số kịch bản đúng hoàn toàn (đúng cả loại sự kiện và kết luận): {sum(r["ok"] for r in ran)}/{len(ran)}',
          '- Lưu ý: bộ kịch bản được thiết kế cùng với các luật heuristic, nên kết quả cho thấy các luật hoạt động đúng như thiết kế, '
          'không phản ánh khả năng phát hiện kỹ thuật tấn công mới chưa có luật.', '']
    out.parent.mkdir(parents=True, exist_ok=True); out.write_text('\n'.join(L), encoding='utf-8')
    return '\n'.join(L)


def main():
    ap = argparse.ArgumentParser(description='FIM benchmark')
    ap.add_argument('--quick', action='store_true', help='ít file và ít lần đo hơn')
    ap.add_argument('--out', default=str(ROOT / 'docs' / 'benchmark_results.md'))
    args = ap.parse_args()
    env = env_info()
    print('[1/3] Hiệu năng quét')
    scan = bench_scan([(100, 4096), (1000, 4096)] if args.quick else
                      [(100, 4096), (1000, 4096), (10000, 4096), (20, 5 * 1024 * 1024)])
    print('[2/3] Độ trễ phát hiện')
    trials = 5 if args.quick else 20
    backend = {'linux': 'inotify', 'win32': 'ReadDirectoryChangesW', 'darwin': 'FSEvents'}.get(sys.platform, sys.platform)
    lat = {f'watchdog ({backend})': bench_latency('watchdog', trials), 'polling': bench_latency('polling', trials)}
    print('[3/3] Độ chính xác phân loại')
    acc = bench_accuracy()
    report(env, scan, lat, acc, Path(args.out))
    print(f'\nĐã ghi kết quả: {args.out}')


if __name__ == '__main__':
    main()
