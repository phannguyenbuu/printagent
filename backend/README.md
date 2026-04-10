# Backend Runbook

Tài liệu này mô tả trạng thái hiện tại của backend Flask trong repo `printagent`.

## Vai trò

Backend chịu trách nhiệm:

- nhận polling từ agent
- lưu latest state + history vào PostgreSQL
- render portal quản trị bằng template server-side
- cung cấp public API cho CRM / client ngoài
- queue lệnh lock/unlock và FTP assignment cho agent

## File quan trọng

- `backend/app.py`: entrypoint, route handlers, page render
- `backend/models.py`: SQLAlchemy models
- `backend/serializers.py`: upsert / serialization helpers
- `backend/utils.py`: normalize MAC/IP, parsing, filter helpers
- `backend/PUBLIC_API.md`: contract chuẩn cho public API
- `backend/templates/`: portal UI + `/api-docs`

## Route groups chính

### UI pages

- `/`
- `/dashboard`
- `/devices`
- `/agents`
- `/lan-sites`
- `/api-docs`
- `/counter`
- `/status`
- `/heatmap`
- `/workspaces`
- `/locations`
- `/materials`
- `/users`
- `/companies`
- `/tasks`
- `/drivers`

### Agent / polling

- `POST /api/agent/register`
- `GET /api/agent/release`
- `POST /api/agent/resolve-lan`
- `GET /api/polling/controls`
- `POST /api/polling/control-result`
- `GET /api/polling/ftp-controls`
- `POST /api/polling/ftp-control-result`
- `POST /api/polling/inventory`
- `POST /api/polling/scan-upload`
- `POST /api/polling`

### Public read-only API

Nguồn chuẩn: `backend/PUBLIC_API.md`

- `GET /machinelist/`
- `GET /networklist/`
- `GET /all/`
- `GET /api/infor/list`
- `GET /api/public/device/by-mac`
- `GET /api/public/device/online-status`
- `GET /api/public/network/by-lan`
- `GET /api/public/device/latest`
- `GET /api/public/agent-machines`

### Device control / operator actions

- `GET /api/devices`
- `GET /api/devices/<printer_id>/events`
- `PATCH /api/devices/<device_ref>/enable`
- `POST /api/devices/<device_ref>/unlock`
- `POST /api/devices/<device_ref>/lock`
- `POST /api/agents/<agent_id>/ftp-sites`

Ghi chú:

- Public contract nên dùng `mac_id`
- Backend hiện vẫn accept numeric legacy id ở `device_ref` để tương thích cũ
- Public request lock/unlock không còn yêu cầu `auth_user` / `auth_password`

## Local run

Linux/macOS:

```bash
cd backend
venv/bin/python app.py
```

Windows PowerShell:

```powershell
cd backend
venv\Scripts\python.exe app.py
```

Các env chính:

- `DATABASE_URL`
- `LEAD_KEYS`
- `SERVER_HOST`
- `SERVER_PORT`
- `SERVER_DEBUG`
- `GOOGLE_DRIVE_SYNC_*`

## Production reality

Trạng thái production đã kiểm tra ngày `2026-04-08`:

- app dir: `/opt/printagent/`
- process thật: `/opt/printagent/venv/bin/python3 /opt/printagent/app.py`
- service thật: `systemctl restart printagent`
- local bind: `127.0.0.1:8005`
- nginx proxy `agentapi.quanlymay.com` vào backend này

Không deploy backend vào `/opt/printagent/backend/`.

## Deploy backend

Cách manual an toàn:

1. backup file cũ trên VPS
2. upload file mới vào `/opt/printagent/`
3. restart service `printagent`
4. verify bằng request read-only hoặc `systemctl status printagent`

Các file thường cần sync:

- `backend/app.py`
- `backend/utils.py`
- `backend/serializers.py`
- `backend/models.py`
- `backend/PUBLIC_API.md`
- `backend/templates/...`

## Ghi chú gần đây

- Device control public đã chuyển sang `mac_id`
- `mac_id` hiện nhận cả:
  - `AA:BB:CC:DD:EE:FF`
  - `AA-BB-CC-DD-EE-FF`
  - `AABBCCDDEEFF`
- Success response luôn normalize về `AA:BB:CC:DD:EE:FF`
- `/api-docs` render trực tiếp từ file `PUBLIC_API.md`, nên nếu đổi API public phải cập nhật file đó cùng lúc
