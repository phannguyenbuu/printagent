# TEST CASE AGENT (VI)

Tài liệu này bám theo agent hiện tại trong thư mục `agent/`.

## 1. Khởi động và cấu hình

| ID | Mục tiêu | Tiền điều kiện | Bước test | Kết quả mong đợi |
|---|---|---|---|---|
| AG-001 | Agent đọc config mặc định | Chưa có override trong DB/env | Chạy `python agent/main.py --mode web` | Agent khởi động, local UI mở ở port `9173` |
| AG-002 | Agent chạy service mode | Config hợp lệ | Chạy `python agent/main.py --mode service` | Polling loop chạy nền, không crash |
| AG-003 | Agent chạy test mode | Có 1 máy Ricoh mẫu | Chạy `python agent/main.py --mode test` | Menu test hoạt động |
| AG-004 | Agent chạy ftp-worker | Config hợp lệ | Chạy `python agent/main.py --mode ftp-worker` | Worker khởi động bình thường |
| AG-005 | Override bằng env | Có env `POLLING_TOKEN` | Chạy agent | Agent dùng token từ env |

## 2. Polling về server

| ID | Mục tiêu | Tiền điều kiện | Bước test | Kết quả mong đợi |
|---|---|---|---|---|
| AG-006 | Register agent thành công | Backend online, token đúng | Chờ startup cycle | `POST /api/agent/register` trả `200` |
| AG-007 | Gửi polling thành công | Có ít nhất 1 máy Ricoh reachable | Chờ 1 chu kỳ | Backend nhận `POST /api/polling` |
| AG-008 | Backend tạm offline | Tắt backend | Chờ 2-3 chu kỳ | Agent không crash, retry ở chu kỳ sau |
| AG-009 | Token sai | Token sai trong config | Chờ polling | Agent log lỗi auth rõ ràng |
| AG-010 | Payload thiếu field phụ | Printer trả dữ liệu thiếu một phần | Polling | Agent vẫn gửi payload hợp lệ, không exception |

## 3. Discovery và MAC mapping

| ID | Mục tiêu | Tiền điều kiện | Bước test | Kết quả mong đợi |
|---|---|---|---|---|
| AG-011 | Discovery thấy máy Ricoh | Máy online trong subnet | Chạy polling cycle | Printer xuất hiện trong inventory |
| AG-012 | Lấy `mac_address` trực tiếp | Máy cho đọc MAC trực tiếp | Polling | MAC lưu đúng vào payload |
| AG-013 | Fallback MAC qua neighbor table | Không đọc được MAC trực tiếp | Polling | Agent vẫn resolve được `mac_address` nếu ARP có dữ liệu |
| AG-014 | Không lấy được MAC | Máy đặc biệt / mạng hạn chế | Polling | Agent không crash, log cảnh báo rõ ràng |

## 4. Parser Ricoh

| ID | Mục tiêu | Tiền điều kiện | Bước test | Kết quả mong đợi |
|---|---|---|---|---|
| AG-015 | Parse counter BW | Có máy BW hoặc fixture HTML | Gọi collect counter | Trả đúng `total`, `copier_bw`, `printer_bw` |
| AG-016 | Parse status | Có máy hoặc fixture HTML | Gọi collect status | Trả `system_status`, toner, tray, alerts |
| AG-017 | Device info | Có máy reachable | Gọi `process_device_info` | Trả model / machine info cần thiết |
| AG-018 | HTML thay đổi nhẹ | Fixture HTML bị lệch marker | Parse | Không crash; trả partial có kiểm soát |

## 5. Lock/unlock qua polling queue

| ID | Mục tiêu | Tiền điều kiện | Bước test | Kết quả mong đợi |
|---|---|---|---|---|
| AG-019 | Nhận lệnh unlock | Backend queue command pending | Chờ `GET /api/polling/controls` | Agent apply unlock và post result |
| AG-020 | Nhận lệnh lock | Backend queue command pending | Chờ polling controls | Agent apply lock và post result |
| AG-021 | Máy không reachable khi control | Tắt máy đích | Queue lock/unlock | Agent post lỗi, backend thấy failed |
| AG-022 | Không có credential local | Bỏ `test.user/password`, máy vẫn chấp nhận login fallback | Queue control | Agent thử fallback hợp lệ theo logic Ricoh |

## 6. FTP queue

| ID | Mục tiêu | Tiền điều kiện | Bước test | Kết quả mong đợi |
|---|---|---|---|---|
| AG-023 | Nhận queue create FTP | Backend queue create | Chờ `GET /api/polling/ftp-controls` | Agent tạo site và post result |
| AG-024 | Nhận queue update FTP | Site đã tồn tại | Queue update | Agent update site đúng |
| AG-025 | Nhận queue delete FTP | Site tồn tại | Queue delete | Agent xoá site và post result |
| AG-026 | `mac_id` không match printer hiện tại | Queue dùng MAC cũ/sai | Agent xử lý queue | Agent trả warning hoặc failed rõ ràng |

## 7. Scan upload

| ID | Mục tiêu | Tiền điều kiện | Bước test | Kết quả mong đợi |
|---|---|---|---|---|
| AG-027 | Upload file scan mới | Bật scan monitoring | Thả file mới vào inbox | Agent upload thành công |
| AG-028 | Không upload trùng | Đã có state file upload | Thả lại file cũ | Agent bỏ qua |
| AG-029 | Upload lỗi tạm thời | Backend scan endpoint lỗi | Chờ chu kỳ scan | Agent log lỗi, retry chu kỳ sau |

## 8. Ổn định

| ID | Mục tiêu | Tiền điều kiện | Bước test | Kết quả mong đợi |
|---|---|---|---|---|
| AG-030 | Chạy liên tục | Môi trường thực | Chạy 24h | Không crash rõ rệt |
| AG-031 | Nhiều máy cùng subnet | >= 10 máy Ricoh | Polling liên tục | Chu kỳ vẫn hoàn thành |
| AG-032 | Restart agent | Kill process rồi chạy lại | Quan sát startup | Agent recover bình thường |

## Ghi chú

- Ưu tiên retest AG-019 -> AG-026 sau mỗi thay đổi liên quan lock/unlock hoặc FTP queue
- Sau khi sửa MAC normalization, retest AG-012, AG-013, AG-026
