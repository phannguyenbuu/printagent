# Agent Notes

Tài liệu này mô tả agent hiện tại trong thư mục `agent/`.

## Vai trò của agent

Agent chạy trong LAN khách hàng và làm các việc sau:

- scan subnet để tìm máy Ricoh
- thu counter, status, device info từ máy
- gửi dữ liệu về backend qua polling HTTP
- nhận queue lock/unlock từ backend
- nhận queue FTP assignment từ backend
- upload file scan nếu bật scan monitoring

## Nguồn sự thật trong code

- runtime entry: `agent/main.py`
- config: `agent/config.py`
- polling loop: `agent/services/polling_bridge.py`
- HTTP client model: `agent/services/api_client.py`
- Ricoh logic: `agent/modules/ricoh/`

## Run modes

Agent hiện support các mode sau:

- `web`
- `service`
- `test`
- `ftp-worker`

Ví dụ:

```bash
python agent/main.py --mode web
python agent/main.py --mode service
python agent/main.py --mode test
python agent/main.py --mode ftp-worker
```

## Port và runtime mặc định

- local web UI port mặc định: `9173`
- local config DB mặc định: `storage/data/agent_config.db`
- scan inbox mặc định: `storage/scans/inbox`
- backend API mặc định: `https://agentapi.quanlymay.com/api`
- polling base URL mặc định: `https://agentapi.quanlymay.com`

## Cấu hình chính

Từ `agent/config.py`, các key cần nhớ:

- `api_url`
- `user_token`
- `test.ip`
- `test.user`
- `test.password`
- `polling.enabled`
- `polling.url`
- `polling.lead`
- `polling.token`
- `polling.interval_seconds`
- `polling.lan_uid`
- `polling.agent_uid`
- `polling.scan_enabled`
- `polling.scan_interval_seconds`
- `polling.scan_dirs`
- `polling.scan_recursive`

`test.user` và `test.password` vẫn là fallback runtime phía agent khi cần login vào máy Ricoh.

## Luồng chính

### Polling cycle

1. resolve LAN identity
2. `POST /api/agent/register`
3. scan máy trong subnet
4. build printer inventory với `mac_address`
5. `POST /api/polling/inventory`
6. `GET /api/polling/controls`
7. apply lock/unlock command nếu có
8. `GET /api/polling/ftp-controls`
9. apply FTP command nếu có
10. thu counter + status + metadata
11. `POST /api/polling`

### Scan upload

Nếu bật `polling.scan_enabled`, agent theo dõi các thư mục scan đã cấu hình và gửi file qua:

- `POST /api/polling/scan-upload`

## Điều quan trọng cần nhớ

- Control flow hiện tại là polling-based, không phải WebSocket-based
- Public lock/unlock request trên server không còn yêu cầu gửi credential, nhưng agent vẫn có thể dùng credential local/fallback để đăng nhập Ricoh nếu cần
- Agent đang dùng `mac_address` để map máy chính xác hơn trong queue FTP và device control

## Cấu trúc thư mục quan trọng

```text
agent/
├─ main.py
├─ config.py
├─ web.py
├─ modules/ricoh/
│  ├─ base.py
│  ├─ collector.py
│  ├─ control.py
│  ├─ address_book.py
│  ├─ wizard.py
│  └─ service.py
├─ services/
│  ├─ api_client.py
│  ├─ polling_bridge.py
│  ├─ updater.py
│  ├─ ftp_worker.py
│  ├─ ftp_control.py
│  ├─ ftp_store.py
│  ├─ scan_drop.py
│  ├─ runtime.py
│  └─ tray.py
└─ templates/
```

## Bẫy tài liệu cũ

- Một số docs cũ còn nhắc `app/` thay vì `agent/`
- Một số docs cũ còn nhắc local UI port `5000`; port hiện tại là `9173`
- Một số docs cũ còn nhắc WebSocket command path; flow hiện tại dựa trên polling bridge

## Khi sửa agent thì update gì

- đổi config key: cập nhật file này + `README.md`
- đổi polling contract: cập nhật file này + `docs/ENDPOINT.md` + `backend/PUBLIC_API.md` nếu public contract bị ảnh hưởng
- đổi local runtime path hoặc port: cập nhật file này ngay
