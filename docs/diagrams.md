# Sơ đồ báo cáo FIM

Nguồn của các hình trong báo cáo. Hình 1, 2, 7, 8, 9 viết bằng Mermaid (xem được trên GitHub, mermaid.live hoặc VS Code có extension Mermaid). Hình 3 đến 6 là file SVG trong `docs/diagrams/`, chèn thẳng vào Word bằng Insert → Pictures.

## Hình 1. Kiến trúc tổng thể

```mermaid
flowchart LR
  subgraph OSL["Hệ điều hành"]
    FS[("Thư mục giám sát<br/>etc · bin · var/log · home")]
    NT["Thông báo thay đổi<br/>inotify / polling qua watchdog"]
  end
  subgraph P1["Thu thập · core.py"]
    SCN["scan_tree()<br/>SHA-256 · size · mtime · mode"]
    CMP["compare_states()<br/>so với baseline hoặc trạng thái trước"]
  end
  subgraph P2["Phân tích · rules.py"]
    CLS["classify()<br/>heuristic → điểm rủi ro"]
    VER{"LEGITIMATE /<br/>SUSPICIOUS"}
  end
  subgraph P3["Lưu trữ · database.py"]
    DB[("SQLite · fim.db<br/>6 bảng")]
    LOG["fim.log · alerts.log"]
  end
  subgraph P4["Trình bày"]
    CLI["CLI · cli.py"]
    WEB["Dashboard · dashboard.py<br/>Flask"]
  end
  MON["Điều phối · service.py<br/>initialize · scan · monitor · accept"]
  CFG["config.json<br/>watch_paths · heuristic · ngưỡng"]
  ADMIN(["Quản trị viên"])
  FS --> NT
  NT -- "sự kiện" --> MON
  CFG -.-> MON
  MON --> SCN
  SCN --> CMP
  CMP -- "danh sách Change" --> CLS
  DB -.->|whitelist| CLS
  CLS --> VER
  VER -- "events, alerts" --> DB
  VER -- "cảnh báo" --> LOG
  DB --> CLI
  DB --> WEB
  ADMIN <--> CLI
  ADMIN <--> WEB
```

## Hình 2. Mô hình triển khai Docker

```mermaid
flowchart LR
  subgraph HOST["Máy host · Windows 11 hoặc Ubuntu"]
    BR["Trình duyệt<br/>127.0.0.1:5000"]
    TERM["Terminal<br/>lệnh docker compose"]
    subgraph ENG["Docker Engine · nhân Linux, có inotify"]
      MONC["Container fim-monitor<br/>image fim-project:2.0 · python:3.13-slim<br/>python main.py monitor"]
      DASH["Container fim-dashboard<br/>image fim-project:2.0 · Flask 3.1.3<br/>python main.py dashboard"]
      VW[("Volume fim-watch<br/>/app/test_folder")]
      VD[("Volume fim-data<br/>/app/data/fim.db")]
      VL[("Volume fim-logs<br/>/app/logs")]
    end
  end
  BR -- "HTTP, cổng 5000" --> DASH
  TERM -- "xem log, chạy kịch bản" --> MONC
  MONC -- "inotify + SHA-256" --> VW
  MONC -- "ghi events, alerts" --> VD
  MONC -- "ghi log" --> VL
  DASH -- "đọc, ack, whitelist" --> VD
  DASH -- "accept: băm lại file" --> VW
```

## Hình 3. Hệ thống giám sát toàn vẹn file (FIM)

![Hình 3](diagrams/usecase_tong_quan.svg)

## Hình 4. Phân rã: Giám sát thời gian thực

![Hình 4](diagrams/usecase_giam_sat.svg)

## Hình 5. Phân rã: Quản lý cảnh báo

![Hình 5](diagrams/usecase_canh_bao.svg)

## Hình 6. Phân rã: Quản lý whitelist

![Hình 6](diagrams/usecase_whitelist.svg)

## Hình 7. Sơ đồ tuần tự luồng chính

```mermaid
sequenceDiagram
  autonumber
  actor KT as Kẻ tấn công
  participant OS as Hệ điều hành<br/>(inotify)
  participant MON as service.monitor()<br/>+ watchdog Observer
  participant CORE as core.py
  participant RU as rules.py<br/>classify()
  participant DB as database.py<br/>FimDB · SQLite
  participant LOG as fim.log<br/>alerts.log
  participant WEB as dashboard.py<br/>Flask
  actor AD as Quản trị viên
  KT->>OS: Sửa etc/config.conf<br/>thêm PermitRootLogin yes
  OS-->>MON: Sự kiện modified
  MON->>MON: on_any_event()<br/>đặt dirty = True
  Note over MON: Chờ debounce 0.5 giây
  MON->>DB: load_current(), ignore_patterns()
  DB-->>MON: Trạng thái trước, pattern ignore
  MON->>CORE: scan_tree(roots, ignore, prev)
  CORE->>CORE: sha256_file()<br/>file đổi size/mtime
  CORE-->>MON: Trạng thái hiện tại
  MON->>CORE: compare_states(prev, cur)
  CORE-->>MON: Change MODIFIED etc/config.conf
  MON->>DB: allow_rules()
  DB-->>MON: Rule whitelist allow
  MON->>RU: classify(change, cfg, allow, batch_size)
  RU-->>MON: Verdict(score 7, HIGH, SUSPICIOUS)
  MON->>DB: record(change, verdict)
  Note over DB: INSERT events<br/>INSERT alerts với status NEW
  DB-->>MON: event_id, alert_id
  MON->>LOG: Log CRITICAL, thêm dòng JSON vào alerts.log
  MON->>DB: replace_current(cur), set_meta(last_scan_at)
  AD->>WEB: GET /alerts
  WEB->>DB: alerts("NEW")
  DB-->>WEB: Danh sách cảnh báo mới
  WEB-->>AD: Trang Cảnh báo
  alt Thay đổi hợp lệ do quản trị viên thực hiện
    AD->>WEB: POST /alerts/1/accept
    WEB->>CORE: service.accept(path) gọi sha256_file()
    WEB->>DB: set_baseline_file(), ack_alert(1)
    WEB-->>AD: Đã chấp nhận<br/>vào baseline
  else Xác định là tấn công
    AD->>WEB: POST /alerts/1/ack
    WEB->>DB: ack_alert(1)
    WEB-->>AD: Đã xác nhận,<br/>giữ nguyên baseline
  end
```

## Hình 8. Sơ đồ hoạt động luồng chính

```mermaid
flowchart TD
  S((" ")) --> A1["Đọc config.json, mở SQLite,<br/>nạp whitelist mặc định"]
  A1 --> D1{"Đã có baseline?"}
  D1 -- "Chưa" --> A2["Quét toàn bộ, băm SHA-256<br/>Lưu baseline và current_state"]
  D1 -- "Có" --> A3["Khởi động watchdog Observer<br/>cho mọi thư mục trong watch_paths"]
  A2 --> A3
  A3 --> A4["Chờ 0.2 giây"]
  A4 --> D2{"Đến hạn quét toàn bộ?<br/>600 giây"}
  D2 -- "Có" --> A5["Full scan: băm lại mọi file"]
  D2 -- "Chưa" --> D3{"Có sự kiện mới và<br/>đã qua debounce 0.5 giây?"}
  D3 -- "Có" --> A6["Quick scan: chỉ băm lại file<br/>đổi size hoặc mtime"]
  A5 --> A7["So sánh với current_state"]
  A6 --> A7
  A7 --> D4{"Có thay đổi?"}
  D4 -- "Có" --> A8["Lấy thay đổi tiếp theo,<br/>tính điểm heuristic"]
  A8 --> D5{"Khớp whitelist allow và<br/>không có dấu hiệu nghiêm trọng?"}
  D5 -- "Có" --> A9["Kết luận LEGITIMATE<br/>Ghi vào bảng events"]
  D5 -- "Không" --> D6{"Điểm ≥ ngưỡng 3?"}
  D6 -- "Không" --> A9
  D6 -- "Có" --> A10["Kết luận SUSPICIOUS<br/>Ghi events, tạo alert NEW<br/>Log cảnh báo, ghi alerts.log"]
  A9 --> D7{"Còn thay đổi?"}
  A10 --> D7
  D7 -- "Còn" --> A8
  D7 -- "Hết" --> A12["Cập nhật current_state<br/>và last_scan_at"]
  D4 -- "Không" --> A12
  A12 --> D9{"Nhận Ctrl+C?"}
  D3 -- "Không" --> D9
  D9 -- "Không" --> A4
  D9 -- "Có" --> A13["Dừng Observer, đóng DB"]
  A13 --> F1(((" ")))
  classDef term fill:#1f2328,stroke:#1f2328,color:#1f2328
  class S,F1 term
```

## Hình 9. Sơ đồ cơ sở dữ liệu

```mermaid
erDiagram
  BASELINE {
    TEXT path PK "đường dẫn tuyệt đối"
    TEXT sha256 "băm SHA-256 nội dung"
    INTEGER size "kích thước, byte"
    INTEGER mtime_ns "thời điểm sửa, ns"
    INTEGER mode "quyền Unix"
  }
  CURRENT_STATE {
    TEXT path PK "đường dẫn tuyệt đối"
    TEXT sha256 "băm SHA-256 nội dung"
    INTEGER size "kích thước, byte"
    INTEGER mtime_ns "thời điểm sửa, ns"
    INTEGER mode "quyền Unix"
  }
  EVENTS {
    INTEGER id PK "tự tăng"
    TEXT timestamp "ISO 8601"
    TEXT path "file thay đổi"
    TEXT event_type "CREATED, MODIFIED, DELETED, MOVED, PERMISSION_CHANGED"
    INTEGER risk_score "điểm heuristic"
    TEXT risk_level "LOW, MEDIUM, HIGH"
    TEXT details "lý do chấm điểm"
    TEXT verdict "LEGITIMATE, SUSPICIOUS"
    TEXT source "monitor, scan"
    TEXT old_path "đường dẫn cũ khi MOVED"
  }
  ALERTS {
    INTEGER id PK "tự tăng"
    INTEGER event_id FK "tham chiếu events.id"
    TEXT timestamp "ISO 8601"
    TEXT path "file liên quan"
    TEXT severity "MEDIUM, HIGH"
    TEXT message "nội dung cảnh báo"
    TEXT status "NEW, ACK"
    TEXT acked_at "thời điểm xác nhận"
  }
  WHITELIST {
    INTEGER id PK "tự tăng"
    TEXT pattern UK "glob, ví dụ *.log"
    TEXT kind UK "ignore, allow"
    TEXT events "* hoặc MODIFIED,CREATED"
    TEXT note "ghi chú"
    TEXT created_at "ISO 8601"
  }
  META {
    TEXT key PK "baseline_at, last_scan_at, whitelist_seeded"
    TEXT value "giá trị"
  }
  EVENTS ||--o| ALERTS : "sinh cảnh báo khi SUSPICIOUS"
  BASELINE |o..o| CURRENT_STATE : "đối chiếu theo path"
```
