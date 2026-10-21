# Hướng dẫn sử dụng FIM

Hướng dẫn cài đặt, cấu hình và vận hành hệ thống giám sát toàn vẹn file (File Integrity Monitoring). Phần kỹ thuật (kiến trúc, bảng tính điểm, kiểm thử) xem thêm ở [README](../README.md).

**Mục lục**
1. [Giới thiệu](#1-giới-thiệu)
2. [Cài đặt và khởi động](#2-cài-đặt-và-khởi-động)
3. [Cấu hình](#3-cấu-hình-configjson)
4. [Sử dụng dashboard](#4-sử-dụng-dashboard)
5. [Sử dụng dòng lệnh](#5-sử-dụng-dòng-lệnh)
6. [Đọc kết quả](#6-đọc-kết-quả)
7. [Quy trình xử lý cảnh báo](#7-quy-trình-xử-lý-cảnh-báo)
8. [Bảo trì](#8-bảo-trì)
9. [Xử lý sự cố](#9-xử-lý-sự-cố)
10. [Câu hỏi thường gặp](#10-câu-hỏi-thường-gặp)

## 1. Giới thiệu

FIM **theo dõi các file quan trọng** trên máy chủ và **báo động khi chúng bị thay đổi một cách đáng ngờ**:

| Chức năng | Mô tả |
|---|---|
| Ghi nhớ trạng thái chuẩn (baseline) | Tính mã băm SHA-256 và lưu kích thước, thời gian sửa, quyền, chủ sở hữu của từng file trong các thư mục được giám sát |
| Theo dõi và phân loại thay đổi | Phát hiện thay đổi gần như tức thì (inotify), chấm điểm rủi ro, kết luận hợp lệ hay đáng ngờ; thay đổi đáng ngờ tạo cảnh báo |
| Quản lý qua web và dòng lệnh | Dashboard xem tổng quan, lịch sử, cảnh báo; quản lý whitelist; xem phạm vi; xử lý cảnh báo |

### Các thành phần

| Thành phần | Vai trò | Khi chạy bằng Docker |
|---|---|---|
| Monitor (`python main.py monitor`) | Chạy nền: theo dõi file, chấm điểm, ghi kết quả | container `fim-monitor` |
| Dashboard (`python main.py dashboard`) | Giao diện web tại http://127.0.0.1:5000 | container `fim-dashboard` |
| CSDL SQLite `data/fim.db` | Baseline, lịch sử sự kiện, cảnh báo, whitelist | volume `fim-data` |
| Log `logs/fim.log`, `logs/alerts.log` | Nhật ký hoạt động; cảnh báo dạng JSON cho SIEM | volume `fim-logs` |
| Cấu hình `config.json` | Thư mục giám sát, whitelist, ngưỡng điểm, giờ làm việc | đóng gói trong image |

### Hai cách sử dụng

| | Cách A: Docker (khuyên dùng) | Cách B: chạy trực tiếp bằng Python |
|---|---|---|
| Dùng khi | Chạy thử, demo, đánh giá hệ thống | Giám sát thư mục thật của máy Linux; hoặc chạy trên Windows |
| Thư mục giám sát | `test_folder` mẫu (etc, bin, var/log, home) bên trong container | Bất kỳ, khai báo trong config (có sẵn `config.linux.json`) |
| Cần cài | Docker Desktop (Windows) hoặc Docker Engine (Linux) | Python 3.13 và thư viện trong `requirements.txt` |

## 2. Cài đặt và khởi động

### 2.1 Yêu cầu
- Windows 10/11, Ubuntu hoặc máy có Docker; RAM trống khoảng 100 MB (monitor dùng 27–32 MB).
- Cổng **5000** chưa bị chương trình khác dùng.
- Mã nguồn: `git clone https://github.com/huukhai243/FIM_Project.git` hoặc giải nén gói zip.

### 2.2 Cách A: chạy bằng Docker
Mở PowerShell (Windows) hoặc Terminal (Linux) **tại thư mục mã nguồn** (thư mục có `docker-compose.yml`):

```bash
docker compose up -d --build      # dựng image và chạy 2 container
docker compose ps                 # kiểm tra: fim-monitor và fim-dashboard đều Up
docker compose logs -f monitor    # xem nhật ký thời gian thực (Ctrl+C để thoát xem, hệ thống vẫn chạy)
```

Mở trình duyệt vào **http://127.0.0.1:5000**. Nhật ký lúc khởi động có 2 dòng `created baseline with 4 file(s)` và `Monitoring (watchdog) 4 path(s)`.

Chạy kịch bản mẫu (2 thay đổi hợp lệ, 6 thao tác mô phỏng tấn công):

```bash
docker compose exec -e DELAY=5 monitor sh tools/demo_attack.sh
```

Khi thuyết trình, dùng script demo từng bước (chạy trên máy host, cần Python 3, không cần cài thêm thư viện). Mỗi thao tác hiện lệnh và ý nghĩa, nhấn Enter mới chạy, rồi in kết quả: hợp lệ hay cảnh báo, mức rủi ro, điểm của từng dấu hiệu. Script tự mở các trang dashboard đúng lúc.

```bash
python tools/demo_live.py --reset   # xóa dữ liệu cũ, dựng lại hệ thống rồi demo đủ 8 bước
python tools/demo_live.py --short   # bản rút gọn: bước 1, 3, 4, 6, 8
python tools/demo_live.py --auto    # chạy thử một mạch, không chờ Enter
```
Khi script chờ Enter: gõ `s` để bỏ qua thao tác đó, `q` để dừng.

> **Lưu ý:** thư mục được giám sát là **volume trong container** (bản sao của `test_folder`). Sửa `test_folder` trên máy host không ảnh hưởng tới container; muốn tạo thay đổi thì dùng `docker compose exec monitor ...`. Mọi lệnh ở mục 5 đều chạy được qua Docker bằng cách thêm `docker compose exec monitor` ở đầu.

### 2.3 Cách B: chạy trực tiếp bằng Python

```bash
# Ubuntu
sudo apt update && sudo apt install -y python3 python3-venv python3-pip
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

```powershell
# Windows PowerShell
py -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Chạy, mỗi lệnh một cửa sổ terminal:

```bash
python main.py init         # tạo baseline lần đầu (monitor cũng tự tạo nếu chưa có)
python main.py monitor      # cửa sổ 1: giám sát thời gian thực
python main.py dashboard    # cửa sổ 2: web tại http://127.0.0.1:5000
```

Trên Windows hệ thống vẫn theo dõi thời gian thực nhưng không xét các dấu hiệu về quyền Unix (setuid, chmod).

### 2.4 Giám sát thư mục hệ thống thật (Linux)
`config.linux.json` giám sát `/etc`, `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/boot`, `/root/.ssh`, `/var/log`. Cần `sudo` để đọc các file như `/etc/shadow`:

```bash
sudo .venv/bin/python main.py --config config.linux.json init
sudo .venv/bin/python main.py --config config.linux.json monitor
sudo .venv/bin/python main.py --config config.linux.json dashboard
```

Gặp lỗi giới hạn inotify khi giám sát nhiều thư mục: `sudo sysctl fs.inotify.max_user_watches=524288`.

### 2.5 Dừng, khởi động lại, xóa dữ liệu (Docker)

| Lệnh | Tác dụng |
|---|---|
| `docker compose stop` / `docker compose start` | Tạm dừng / chạy lại, giữ nguyên dữ liệu |
| `docker compose restart monitor` | Khởi động lại riêng monitor |
| `docker compose down` | Dừng và xóa container, **giữ** dữ liệu |
| `docker compose down -v` | Dừng và **xóa toàn bộ dữ liệu**: baseline, lịch sử, cảnh báo, thư mục giám sát về trạng thái gốc |
| `docker compose up -d --build` | Dựng lại image (sau khi sửa code hoặc `config.json`) rồi chạy |

## 3. Cấu hình (config.json)

| Tham số | Ý nghĩa | Mặc định |
|---|---|---|
| `watch_paths` | Thư mục giám sát; mỗi mục có `path`, `label`, `critical` (true: thay đổi bị +2 điểm) | etc, bin (critical); var/log, home |
| `database`, `log_file` | Đường dẫn CSDL và file log | `data/fim.db`, `logs/fim.log` |
| `whitelist` | Rule **ignore** mặc định | `*.tmp`, `*.swp`, `~*`, `__pycache__/`, `*.pyc` |
| `allowed_changes` | Rule **allow** mặc định, kèm loại sự kiện | `*.log` với `CREATED,MODIFIED` |
| `sensitive_paths` | Mẫu đường dẫn nhạy cảm (+3 điểm) | `*.conf`, `*.ini`, `*.service`, `*.sh`, `passwd`, `shadow`, `sudoers`, `authorized_keys`, `*/etc/*`, `*/bin/*` |
| `executable_extensions` | Đuôi file thực thi (+2 điểm) | `.sh .py .bin .exe .elf .so` |
| `suspicious_extensions` | Đuôi kiểu ransomware (+4 điểm) | `.locked .encrypted .enc .crypt .crypto .ransom` |
| `suspicious_threshold` | Từ mức điểm này trở lên là đáng ngờ, tạo cảnh báo | `3` |
| `mass_change_threshold`, `mass_change_window_seconds` | Bao nhiêu thay đổi trong bao nhiêu giây thì tính là hàng loạt (+3 điểm) | 10 file / 60 giây |
| `work_hours` | Giờ làm việc; thay đổi ngoài khung này +1 điểm | `[7, 19]` |
| `debounce_seconds`, `max_event_delay_seconds` | Chờ thao tác lắng xuống bao lâu rồi quét; chờ tối đa bao lâu | 0,5 s; 2 s |
| `poll_interval_seconds` | Chu kỳ quét khi phải dùng polling | 1 s |
| `full_scan_interval_seconds` | Chu kỳ băm lại toàn bộ file (bắt sửa lén) | 600 s |
| `force_polling` (tùy chọn) | `true`: buộc dùng polling thay cho inotify | không đặt |
| `check_unix_permissions` (tùy chọn) | Có xét quyền Unix hay không | `true` trên Linux, `false` trên Windows |

Ví dụ thêm một thư mục giám sát:

```json
{"path": "test_folder/opt", "label": "Ứng dụng", "critical": false}
```

**Áp dụng cấu hình mới:** chạy bằng Docker thì `docker compose up -d --build` (config được đóng gói trong image); chạy trực tiếp thì dừng (Ctrl+C) và chạy lại monitor, dashboard.

> Khi thêm thư mục giám sát, file trong thư mục mới sẽ bị báo là "file mới". Sau khi kiểm tra, cập nhật baseline bằng nút **Chấp nhận trạng thái hiện tại làm baseline mới** (trang Phạm vi giám sát) hoặc `python main.py accept --all`.

## 4. Sử dụng dashboard

Mở **http://127.0.0.1:5000**. Số đỏ cạnh chữ **Cảnh báo** là số cảnh báo chưa xử lý. Dashboard chỉ mở trên máy đang chạy hệ thống và không có đăng nhập.

| Trang | Dùng để |
|---|---|
| **Tổng quan** | Số cảnh báo chưa xử lý, tổng sự kiện, đáng ngờ / hợp lệ, file trong baseline, biểu đồ theo ngày, theo mức rủi ro, theo loại thay đổi, file thay đổi nhiều nhất. Tự làm mới mỗi 10 giây |
| **Lịch sử thay đổi** | Mọi thay đổi (kể cả hợp lệ), 50 dòng mỗi trang. Lọc theo đường dẫn hoặc lý do, kết luận, mức, loại thay đổi, nguồn (monitor/scan) |
| **Cảnh báo** | Danh sách cảnh báo, lọc Chưa xử lý / Đã xử lý / Tất cả, xử lý từng cảnh báo |
| **Whitelist** | Thêm, xóa rule `ignore` / `allow`; có hiệu lực ngay, không cần khởi động lại |
| **Phạm vi giám sát** | Thư mục, nhãn, mức quan trọng, số file và dung lượng trong baseline, trạng thái; cập nhật toàn bộ baseline |

Các nút trên trang Cảnh báo:

| Nút | Hệ thống làm gì | Dùng khi |
|---|---|---|
| **Xác nhận** | Đổi trạng thái NEW → ACK; baseline giữ nguyên | Đã xem, đang hoặc đã xử lý (ví dụ thay đổi do tấn công) |
| **Chấp nhận vào baseline** | Băm lại file, ghi vào baseline, đồng thời xác nhận | Thay đổi hợp lệ: lần sau không báo nữa |
| **Xác nhận tất cả** | Xác nhận mọi cảnh báo đang chờ | Sau khi đã kiểm tra hết |

Mọi nút đều kèm mã chống giả mạo yêu cầu (CSRF). Nếu thấy dòng đỏ *"Phiên làm việc không hợp lệ hoặc đã hết hạn"*, tải lại trang (F5) rồi thao tác lại.

## 5. Sử dụng dòng lệnh

Cách gọi: `python main.py <lệnh>`; qua Docker: `docker compose exec monitor python main.py <lệnh>`; dùng cấu hình khác: `python main.py --config config.linux.json <lệnh>`.

| Lệnh | Tác dụng |
|---|---|
| `init` | Tạo (hoặc tạo lại) baseline |
| `monitor` | Giám sát thời gian thực |
| `scan [--record]` | So trạng thái hiện tại với baseline; `--record`: ghi vào lịch sử và tạo cảnh báo |
| `events [--limit N] [--level HIGH] [--verdict SUSPICIOUS]` | Lịch sử thay đổi |
| `alerts [--all] [--limit N]` | Cảnh báo (mặc định chỉ chưa xử lý) |
| `ack ID... \| --all` | Xác nhận cảnh báo |
| `accept --path FILE \| --all` | Chấp nhận một file, hoặc toàn bộ trạng thái hiện tại, vào baseline |
| `whitelist [list]` | Xem whitelist |
| `whitelist add "MẪU" [--kind ignore\|allow] [--events ...] [--note ...]` | Thêm rule |
| `whitelist remove ID` | Xóa rule |
| `scope` | Thư mục giám sát và số file trong baseline |
| `dashboard [--host ...] [--port 5000]` | Chạy web dashboard |

Ví dụ:

```bash
python main.py events --verdict SUSPICIOUS --level HIGH
python main.py ack 3 5 7
python main.py accept --path test_folder/etc/ntp.conf
python main.py whitelist add "*.cache" --kind allow --events CREATED,MODIFIED --note "cache ứng dụng"
```

## 6. Đọc kết quả

### 6.1 Một dòng nhật ký

```text
20:05:10 | CRITICAL | ALERT #1 [SUSPICIOUS/HIGH] MODIFIED | test_folder/etc/config.conf | score=8 | content changed, critical directory (Cấu hình hệ thống), sensitive path, outside work hours (7h-19h)
```

| Phần | Nghĩa |
|---|---|
| `CRITICAL` / `WARNING` / `INFO` | Mức HIGH (đỏ) / MEDIUM (vàng) / hợp lệ (xanh) |
| `ALERT #1` | Số cảnh báo (chỉ thay đổi đáng ngờ mới có) |
| `[SUSPICIOUS/HIGH]` | Kết luận (SUSPICIOUS / LEGITIMATE) và mức rủi ro |
| `MODIFIED` | Loại thay đổi: CREATED, MODIFIED, DELETED, MOVED, PERMISSION_CHANGED, OWNER_CHANGED, TIMESTAMP_CHANGED |
| `score=8` và phần cuối | Tổng điểm và các lý do được cộng điểm (bảng điểm: [README](../README.md#phân-loại--chấm-điểm)) |

### 6.2 Mức rủi ro và kết luận

| Tổng điểm | Mức | Kết luận | Hệ thống làm gì |
|---|---|---|---|
| 0 – 2 | LOW | LEGITIMATE | Chỉ ghi lịch sử |
| 3 – 4 | MEDIUM | SUSPICIOUS | Ghi lịch sử + tạo cảnh báo |
| từ 5 | HIGH | SUSPICIOUS | Ghi lịch sử + tạo cảnh báo |

Thay đổi khớp rule `allow` là hợp lệ dù điểm cao, **trừ** 4 dấu hiệu nghiêm trọng mà whitelist không che được: làm rỗng file, bật setuid/setgid, đuôi kiểu ransomware, lùi thời gian sửa (log ghi `whitelist '...' overridden`).

### 6.3 File log và tích hợp SIEM
- `logs/fim.log`: toàn bộ nhật ký. Xem: `docker compose exec monitor tail -f logs/fim.log`.
- `logs/alerts.log`: mỗi cảnh báo một dòng JSON, đẩy được sang SIEM (Wazuh, ELK...). Ví dụ:

```json
{"alert_id": 1, "event_id": 3, "time": "2026-10-21T20:05:10+07:00", "path": "/app/test_folder/etc/config.conf", "event": "MODIFIED", "severity": "HIGH", "score": 8, "reasons": ["content changed", "critical directory (Cấu hình hệ thống)", "sensitive path", "outside work hours (7h-19h)"]}
```

## 7. Quy trình xử lý cảnh báo

Hệ thống chỉ **phát hiện và cảnh báo**, không tự sửa hay khôi phục file; quyết định thuộc về quản trị viên.

1. **Đọc cảnh báo:** file nào, loại thay đổi gì, mức nào, lý do gì.
2. **Xem bối cảnh:** trang Lịch sử, tìm theo đường dẫn file để xem các thay đổi trước đó và cùng thời điểm.
3. **Xử lý theo tình huống:**

| Tình huống | Việc cần làm | Thao tác |
|---|---|---|
| Tấn công, thay đổi trái phép | Điều tra; khôi phục file từ bản sao lưu; xử lý lỗ hổng; **không** chấp nhận vào baseline | **Xác nhận** / `ack ID` |
| Thay đổi hợp lệ một lần (sửa cấu hình theo kế hoạch) | Kiểm tra đúng là thay đổi đã lên kế hoạch | **Chấp nhận vào baseline** / `accept --path FILE` |
| Thay đổi hợp lệ lặp lại (log, file tạm, cache) | Thêm whitelist: `ignore` nếu không cần theo dõi, `allow` nếu vẫn muốn ghi lịch sử | Trang **Whitelist** / `whitelist add` |
| Đợt cập nhật lớn (cài, gỡ, nâng cấp phần mềm) | Xác minh nguồn cập nhật, rồi cập nhật toàn bộ baseline | **Chấp nhận trạng thái hiện tại làm baseline mới** + **Xác nhận tất cả** / `accept --all`, `ack --all` |

> Chấp nhận toàn bộ làm baseline mới sẽ coi **mọi** trạng thái hiện tại là chuẩn, kể cả thay đổi do kẻ tấn công nếu có. Chỉ làm sau khi đã kiểm tra hết các cảnh báo.

Công việc định kỳ: hằng ngày đưa "Cảnh báo chưa xử lý" về 0; hằng tuần xem Lịch sử lọc mức HIGH và rà lại whitelist; định kỳ sao lưu CSDL và kiểm tra trang Phạm vi (mọi thư mục đều OK).

## 8. Bảo trì

| Việc | Lệnh (Docker) |
|---|---|
| Sao lưu CSDL | `docker compose cp monitor:/app/data/fim.db ./fim_backup.db` |
| Xem trạng thái, tài nguyên | `docker compose ps` · `docker stats fim-monitor fim-dashboard` |
| Cập nhật phiên bản mới | `git pull` rồi `docker compose up -d --build` |
| Chạy kiểm thử tự động | `docker compose exec monitor python -m unittest discover -s tests` |
| Đặt lại hệ thống từ đầu | `docker compose down -v` rồi `docker compose up -d --build` |

Trên Linux, file CSDL chỉ tài khoản chạy FIM đọc, ghi được (quyền 600). Người có quyền root vẫn có thể sửa CSDL hoặc tắt monitor, nên đẩy `alerts.log` sang máy khác (SIEM) để giữ bằng chứng.

## 9. Xử lý sự cố

| Hiện tượng | Nguyên nhân | Cách xử lý |
|---|---|---|
| `failed to connect to the docker API ... dockerDesktopLinuxEngine` | Docker Desktop chưa bật | `docker desktop start`, chờ Engine running |
| `no configuration file provided` | Không đứng ở thư mục mã nguồn | `cd` tới thư mục có `docker-compose.yml` |
| `port is already allocated` (5000) | Chương trình khác đang dùng cổng 5000 | Tắt chương trình đó, hoặc đổi cổng ở mục `ports` trong `docker-compose.yml` |
| Sửa `test_folder` trên máy host nhưng không có cảnh báo | Container giám sát volume riêng | Tạo thay đổi bằng `docker compose exec monitor ...` |
| Sửa `config.json` không có tác dụng (Docker) | Config đóng gói trong image | `docker compose up -d --build` |
| Dòng đỏ "Phiên làm việc không hợp lệ..." | Mã bảo vệ của trang đã cũ | Tải lại trang (F5) |
| `path(s) skipped (missing or not readable)` | Không đủ quyền đọc file | Linux thật: chạy bằng `sudo` |
| Log báo dùng polling thay vì watchdog | Chưa cài watchdog | `pip install -r requirements.txt` |
| Điểm cao hơn mong đợi đúng 1 | Thay đổi xảy ra ngoài giờ làm việc | Bình thường; chỉnh `work_hours` nếu cần |
| Windows: đổi quyền file không bị phát hiện | Quyền Unix chỉ xét trên Linux | Bình thường; dùng Docker hoặc Linux |

## 10. Câu hỏi thường gặp

**Hệ thống có tự khôi phục file bị sửa không?** Không. FIM chỉ phát hiện và cảnh báo; khôi phục file là việc của quản trị viên.

**Tắt monitor rồi bật lại có bỏ sót thay đổi không?** Không. Khi bật lại, monitor so trạng thái trên đĩa với trạng thái đã lưu nên vẫn phát hiện các thay đổi xảy ra lúc tắt. Lệnh `scan` so với baseline bất cứ lúc nào.

**Kẻ tấn công sửa file nhưng giữ nguyên kích thước và thời gian sửa thì sao?** Lần quét nhanh có thể bỏ qua, nhưng lần quét toàn bộ định kỳ (mặc định 10 phút) băm lại mọi file nên vẫn phát hiện. Muốn nhanh hơn thì giảm `full_scan_interval_seconds`.

**Mở dashboard từ máy khác được không?** Không, có chủ ý: dashboard chỉ nghe trên 127.0.0.1 và chưa có đăng nhập.

**Có gửi email hay tin nhắn khi có cảnh báo không?** Chưa. Cảnh báo được ghi vào `alerts.log` dạng JSON để chuyển sang SIEM.

**Tốn bao nhiêu tài nguyên?** Monitor dùng 27–32 MB RAM, CPU gần 0% khi không có thay đổi; độ trễ phát hiện trung bình khoảng 0,63 giây.
