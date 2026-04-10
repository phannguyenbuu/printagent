# GoPrinx / PrintAgent

Hệ thống quản lý máy Ricoh gồm 3 phần:

- `agent/`: agent chạy trong LAN, scan máy, polling dữ liệu, nhận lệnh lock/unlock và FTP queue
- `backend/`: Flask server + PostgreSQL, nhận polling, render portal quản trị, public API
- `app-gox/`: frontend React/Vite cho portal người dùng

## Trạng thái hiện tại

Snapshot này phản ánh trạng thái repo và production đã kiểm tra ngày `2026-04-08`.

- Public API production: `https://agentapi.quanlymay.com`
- Frontend production: `https://app.quanlymay.com`
- Backend production chạy trực tiếp tại `/opt/printagent/`
- Service thật trên VPS là `systemd`: `systemctl restart printagent`
- Nginx proxy `agentapi.quanlymay.com` vào `127.0.0.1:8005`
- Trang docs public render từ file `backend/PUBLIC_API.md` qua route `/api-docs`

## Điều quan trọng cần nhớ khi quay lại

1. Repo hiện dùng `agent/` và `backend/`. Nhiều docs cũ vẫn nhắc `app/` và `server/`; coi đó là legacy.
2. Production không dùng `pm2 restart printagent-server` cho backend này nữa. Dùng `systemctl restart printagent`.
3. Device control public dùng `mac_id`, không còn dùng `printer_id` làm contract chính.
4. `POST /api/devices/<mac_id>/lock|unlock` và `PATCH /api/devices/<mac_id>/enable` không còn yêu cầu `auth_user` / `auth_password` trong request body.
5. Server hiện nhận `mac_id` theo 3 dạng:
   - `AA:BB:CC:DD:EE:FF`
   - `AA-BB-CC-DD-EE-FF`
   - `AABBCCDDEEFF`

## Nên đọc gì trước

- `README.md`: overview + production reality
- `backend/PUBLIC_API.md`: contract public API chuẩn
- `docs/ENDPOINT.md`: bản đồ endpoint nội bộ
- `docs/AGENTS.md`: agent runtime và cấu hình
- `docs/GEMINI.md`: ghi chú handover / memory khi quay lại dự án
- `backend/README.md`: runbook riêng cho backend

## Cấu trúc repo

```text
printagent/
├─ agent/                  Agent Windows + local web UI
├─ backend/                Flask server, templates, SQLAlchemy models
├─ app-gox/                React/Vite frontend
├─ docs/                   Handover docs, endpoint map, test plans
├─ scripts/deploy/         Các script deploy; có cả script current lẫn legacy
├─ storage/                Dữ liệu cục bộ/dev
└─ dist/                   Output build agent exe
```

## Chạy local

### Backend

```bash
cd backend
venv/bin/python app.py
```

Windows:

```powershell
cd backend
venv\Scripts\python.exe app.py
```

Mặc định backend đọc `.env` từ thư mục hiện tại hoặc từ `backend/.env`.

### Frontend

```bash
cd app-gox
npm install
npm run dev
```

### Agent

```bash
python agent/main.py --mode web
python agent/main.py --mode service
python agent/main.py --mode test
python agent/main.py --mode ftp-worker
```

Agent local web UI hiện dùng port mặc định `9173`.

## Deploy

### Backend

Cách an toàn nhất hiện tại là copy thủ công các file đã đổi lên `/opt/printagent/`, rồi restart:

```bash
systemctl restart printagent
systemctl status printagent --no-pager
```

Lưu ý:

- `scripts/deploy/` có cả script đúng path mới lẫn script cũ còn trỏ sang `server/` hoặc `pm2`.
- Trước khi chạy script deploy, luôn đọc nhanh remote path của script đó.
- Các file backend live trên VPS nằm trực tiếp tại `/opt/printagent/app.py`, `/opt/printagent/utils.py`, `/opt/printagent/templates/...`, không phải `/opt/printagent/backend/...`.

### Frontend

Script đang có trong repo:

- `scripts/deploy/deploy_frontend.py`
- Upload `app-gox/dist/` lên `/var/www/app-gox`

### Agent EXE

Build:

```powershell
.\build_agent_exe.ps1
```

Deploy:

- `scripts/deploy/deploy_agent_exe.py`
- Upload `dist/printagent.exe` lên `/opt/printagent/static/releases/printagent.exe`
- Upload manifest từ `backend/storage/releases/agent_release.json`

## Các luồng chính

### Polling

1. Agent scan LAN, nhận diện máy Ricoh
2. Agent thu `counter`, `status`, `device info`
3. Agent gửi `POST /api/polling`
4. Backend upsert dữ liệu latest vào `DeviceInfor` và lưu history vào `CounterInfor`, `StatusInfor`

### Device control

1. Client gọi `POST /api/devices/<mac_id>/unlock` hoặc `lock`
2. Backend queue `PrinterControlCommand`
3. Agent lấy lệnh qua polling controls
4. Agent thao tác lên máy Ricoh
5. Backend nhận result và trả `200`, `409`, hoặc `504`

### FTP queue

1. Client gọi `POST /api/agents/<agent_id>/ftp-sites`
2. Backend queue `FtpControlCommand`
3. Agent lấy queue qua polling
4. Agent tự suy ra FTP runtime nội bộ từ `mac_id + scan_path`, rồi apply scan destination

## Các file đáng tin cậy nhất

- Route thực tế: `backend/app.py`
- Normalize MAC/IP và helper: `backend/utils.py`
- Public API contract: `backend/PUBLIC_API.md`
- Agent runtime config: `agent/config.py`
- Polling control loop: `agent/services/polling_bridge.py`

## Các bẫy tài liệu cũ

- Tài liệu cũ có thể nhắc:
  - `server/` thay vì `backend/`
  - `app/` thay vì `agent/`
  - WebSocket control flow cũ
  - `pm2 restart printagent-server`
  - `/api/printer/<id>/lock`
- Các nội dung đó không còn là nguồn sự thật chính.

## Gợi ý khi tiếp tục phát triển

- Nếu thay public API, sửa `backend/PUBLIC_API.md` trước, rồi mới sửa docs còn lại.
- Nếu thay polling/control flow, sửa `docs/AGENTS.md` và `docs/ENDPOINT.md`.
- Nếu thay deploy production, cập nhật ngay `README.md` và `docs/GEMINI.md`.
