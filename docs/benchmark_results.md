# Kết quả kiểm thử & đo đạc FIM

## Môi trường đo

| Thông số | Giá trị |
|---|---|
| Thời điểm đo | 2026-10-03 21:35 |
| Hệ điều hành | Windows-11-10.0.26200-SP0 |
| CPU | Intel64 Family 6 Model 189 Stepping 1, GenuineIntel (8 luồng) |
| Python | 3.13.15 |
| SQLite | 3.50.4 |
| watchdog | 6.0.0 |
| Flask | 3.1.3 |
| FIM | 2.0.0 |

## 1. Hiệu năng quét

Full scan = đọc và tính SHA-256 toàn bộ file (dùng cho `init`, `scan`, `accept`). Quick scan = chỉ hash lại file có size/mtime thay đổi (dùng khi `monitor` nhận sự kiện). Đo khi file đã nằm trong page cache của hệ điều hành. Với file nhỏ, chi phí mở file chiếm phần lớn (trên Windows còn bị phần mềm diệt virus quét khi mở file), nên tốc độ tính theo file/s quan trọng hơn MB/s.

| Số file | Kích thước/file | Tổng dung lượng | Full scan (s) | Tốc độ (file/s) | Thông lượng (MB/s) | Quick scan (s) | Quick nhanh hơn |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 100 | 4 KB | 0.4 MB | 0.080 | 1,245 | 4.9 | 0.007 | 11.6x |
| 1,000 | 4 KB | 3.9 MB | 0.976 | 1,025 | 4.0 | 0.068 | 14.4x |
| 10,000 | 4 KB | 39.1 MB | 12.493 | 800 | 3.1 | 0.744 | 16.8x |
| 20 | 5 MB | 100.0 MB | 0.166 | 120 | 602.2 | 0.002 | 83.0x |

## 2. Độ trễ phát hiện

Từ lúc ghi vào `etc/app.conf` đến lúc sự kiện xuất hiện trong bảng `events`. `debounce_seconds = 0.5`, `poll_interval_seconds = 1.0`.

| Cơ chế | Số lần đo | Phát hiện | Min (s) | Trung bình (s) | Trung vị (s) | P95 (s) | Max (s) |
|---|---:|---:|---:|---:|---:|---:|---:|
| watchdog (ReadDirectoryChangesW) | 20 | 20/20 | 0.525 | 0.634 | 0.644 | 0.718 | 0.728 |
| polling | 20 | 20/20 | 0.058 | 0.522 | 0.381 | 0.985 | 0.994 |

Watchdog: sự kiện đến gần như tức thời, độ trễ chủ yếu do `debounce` (chờ 0.5 s không có sự kiện mới) + chu kỳ vòng lặp 0.2 s. Polling: trung bình nửa chu kỳ quét + thời gian quét.

**Chi phí khi không có thay đổi** (ước tính từ thời gian quick scan ở mục 1, polling mỗi 1 s):

| Số file giám sát | Polling: thời gian quét mỗi chu kỳ | Tỉ lệ thời gian bận (ước tính) | Watchdog |
|---:|---:|---:|---|
| 100 | 0.007 s | 1% | ≈ 0 (chỉ quét khi có sự kiện) |
| 1,000 | 0.068 s | 7% | ≈ 0 (chỉ quét khi có sự kiện) |
| 10,000 | 0.744 s | 74% | ≈ 0 (chỉ quét khi có sự kiện) |

## 3. Độ chính xác phân loại

Mỗi kịch bản chạy trên môi trường sạch: tạo baseline → thực hiện hành động → `scan`. `work_hours = [0, 24]` để loại yếu tố giờ làm việc.

| # | Kịch bản | Mong đợi | Thực tế | Điểm | Kết quả |
|---:|---|---|---|---:|:---:|
| 1 | Tạo ghi chú mới trong home | CREATED / LEGITIMATE | CREATED / LEGITIMATE | 1 | ✅ |
| 2 | Sửa ghi chú trong home | MODIFIED / LEGITIMATE | MODIFIED / LEGITIMATE | 2 | ✅ |
| 3 | Ứng dụng ghi thêm log | MODIFIED / LEGITIMATE | MODIFIED / LEGITIMATE | 2 | ✅ |
| 4 | Tạo file log mới (log rotation) | CREATED / LEGITIMATE | CREATED / LEGITIMATE | 1 | ✅ |
| 5 | Tạo file tạm *.tmp (whitelist ignore) | không có sự kiện | không có sự kiện | - | ✅ |
| 6 | Chỉ đổi mtime, nội dung giữ nguyên | không có sự kiện | không có sự kiện | - | ✅ |
| 7 | Sửa file cấu hình trong etc | MODIFIED / SUSPICIOUS | MODIFIED / SUSPICIOUS | 7 | ✅ |
| 8 | Tạo file cấu hình mới trong etc | CREATED / SUSPICIOUS | CREATED / SUSPICIOUS | 6 | ✅ |
| 9 | Thay thế chương trình trong bin | MODIFIED / SUSPICIOUS | MODIFIED / SUSPICIOUS | 9 | ✅ |
| 10 | Xóa chương trình trong bin | DELETED / SUSPICIOUS | DELETED / SUSPICIOUS | 10 | ✅ |
| 11 | Tạo file ẩn (backdoor) trong home | CREATED / SUSPICIOUS | CREATED / SUSPICIOUS | 3 | ✅ |
| 12 | Đổi tên file sang .locked (ransomware) | MOVED / SUSPICIOUS | MOVED / SUSPICIOUS | 8 | ✅ |
| 13 | Tạo 12 file .enc cùng lúc | CREATED / SUSPICIOUS | CREATED / SUSPICIOUS | 8 | ✅ |
| 14 | Xóa file log (xóa dấu vết) | DELETED / SUSPICIOUS | DELETED / SUSPICIOUS | 3 | ✅ |
| 15 | Làm rỗng file log (xóa dấu vết) | MODIFIED / SUSPICIOUS | MODIFIED / SUSPICIOUS | 4 | ✅ |
| 16 | chmod 600 ghi chú (thu hẹp quyền) | PERMISSION_CHANGED / LEGITIMATE | *chỉ chạy trên Linux* | - | N/A |
| 17 | chmod +x file trong home | PERMISSION_CHANGED / SUSPICIOUS | *chỉ chạy trên Linux* | - | N/A |
| 18 | chmod u+s script trong bin (setuid) | PERMISSION_CHANGED / SUSPICIOUS | *chỉ chạy trên Linux* | - | N/A |

**Ma trận nhầm lẫn** (15 kịch bản đã chạy, 3 kịch bản chỉ chạy trên Linux):

| | Hệ thống báo SUSPICIOUS | Hệ thống báo LEGITIMATE / không báo |
|---|---:|---:|
| **Thực tế là tấn công** | TP = 9 | FN = 0 |
| **Thực tế là hợp lệ** | FP = 0 | TN = 6 |

- Accuracy = 100%  ·  Precision = 100%  ·  Recall = 100%
- Số kịch bản đúng hoàn toàn (đúng cả loại sự kiện và kết luận): 15/15
- Lưu ý: bộ kịch bản được thiết kế cùng với các luật heuristic, nên kết quả cho thấy các luật hoạt động đúng như thiết kế, không phản ánh khả năng phát hiện kỹ thuật tấn công mới chưa có luật.
