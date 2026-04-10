# Endpoint Map

Tài liệu này là bản đồ nhanh để quay lại codebase. Đây không phải contract chi tiết cho mọi payload.

Nguồn chuẩn cho public API:

- `backend/PUBLIC_API.md`

Nguồn chuẩn cho route thật:

- `backend/app.py`

## 1. UI pages

Các page render bằng backend template:

- `/`
- `/dashboard`
- `/devices`
- `/infor`
- `/api-docs`
- `/lan-sites`
- `/agents`
- `/counter`
- `/status`
- `/heatmap`
- `/leads`
- `/workspaces`
- `/locations`
- `/repairs`
- `/materials`
- `/scan`
- `/users`
- `/companies`
- `/tasks`
- `/drivers`

## 2. Agent / polling endpoints

Đây là nhóm endpoint quan trọng nhất cho data plane:

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

Ghi nhớ:

- Lock/unlock và FTP assignment đều đi qua polling queue
- Agent không còn phụ thuộc vào WebSocket realtime để nhận control command

## 3. Public read-only API

Các endpoint này được client ngoài đọc trực tiếp:

- `GET /machinelist/`
- `GET /networklist/`
- `GET /all/`
- `GET /api/infor/list`
- `GET /api/public/device/by-mac`
- `GET /api/public/device/online-status`
- `GET /api/public/network/by-lan`
- `GET /api/public/device/latest`
- `GET /api/public/agent-machines`

Ghi nhớ:

- `mac_id` hiện nhận colon, dash, hoặc compact 12 ký tự
- response normalize lại `mac_id` về dạng colon-separated

## 4. Device control / operator endpoints

- `GET /api/devices`
- `GET /api/devices/<printer_id>/events`
- `PATCH /api/devices/<device_ref>/enable`
- `POST /api/devices/<device_ref>/unlock`
- `POST /api/devices/<device_ref>/lock`
- `POST /api/devices/<device_ref>/scan-folder`
- `POST /api/agents/<agent_id>/ftp-sites`
  - legacy alias nếu client đã biết đúng `agent_id`

Contract public nên dùng:

- `/api/devices/<mac_id>/unlock`
- `/api/devices/<mac_id>/lock`
- `/api/devices/<mac_id>/enable`
- `/api/devices/<mac_id>/scan-folder`

`/api/devices/<mac_id>/scan-folder`:
- server resolve printer theo MAC, lấy `lan_uid`, rồi chọn agent cùng LAN để queue command
- preferred body for create: `scan_path`
- preferred body for update/delete: `site_name` (+ `scan_path` nếu update)

`device_ref` trong code vẫn accept numeric id cũ để tương thích.

## 5. Dashboard / analytics

- `GET /api/dashboard/summary`
- `GET /api/counter/timelapse`
- `GET /api/status/timelapse`
- `GET /api/counter/trend`
- `GET /api/counter/heatmap`
- `DELETE /api/counter/<row_id>`
- `PATCH /api/counter/<row_id>/favorite`
- `DELETE /api/status/<row_id>`
- `PATCH /api/status/<row_id>/favorite`
- `DELETE /api/infor/<row_id>`

## 6. Task / CRUD APIs

- `GET|POST /api/tasks`
- `PATCH|DELETE /api/tasks/<task_id>`
- `GET|POST /api/workspaces`
- `PATCH|DELETE /api/workspaces/<ws_id>`
- `GET|POST /api/locations`
- `PATCH|DELETE /api/locations/<loc_id>`
- `GET|POST /api/materials`
- `PATCH|DELETE /api/materials/<mat_id>`
- `GET|POST /api/users`
- `PATCH|DELETE /api/users/<user_id>`
- `GET|POST /api/networks`
- `PATCH|DELETE /api/networks/<net_id>`
- `GET /api/user/workspaces`
- `GET /api/workspace/users`
- `POST /api/login`
- `POST /api/login/google`
- `GET /api/drivers/<brand>`

## 7. Khi cần update docs

- Nếu đổi public API: sửa `backend/PUBLIC_API.md` trước
- Nếu đổi route thật: sửa `backend/app.py`, rồi cập nhật file này
- Nếu đổi polling flow hoặc agent contract: sửa thêm `docs/AGENTS.md`
