# Project Memory

File này dùng như handover note để lần sau quay lại dự án nhanh hơn.

## Snapshot hiện tại

Ngày kiểm tra gần nhất: `2026-04-08`

- API production: `https://agentapi.quanlymay.com`
- Frontend production: `https://app.quanlymay.com`
- Backend live files nằm trực tiếp ở `/opt/printagent/`
- Backend service thật: `systemctl restart printagent`
- Local bind của backend production: `127.0.0.1:8005`
- Public docs page: `/api-docs`

## Các thay đổi quan trọng gần đây

### Device control contract

Đã chuyển contract public sang:

- `POST /api/devices/<mac_id>/unlock`
- `POST /api/devices/<mac_id>/lock`
- `PATCH /api/devices/<mac_id>/enable`

Không còn dùng `printer_id` như contract chính cho client ngoài.

### Credentials

Public request lock/unlock không còn yêu cầu:

- `auth_user`
- `auth_password`

Agent/backend vẫn có thể giữ credential nội bộ để thực thi login lên Ricoh khi cần.

### MAC normalization

Server hiện accept cả 3 dạng:

- `AA:BB:CC:DD:EE:FF`
- `AA-BB-CC-DD-EE-FF`
- `AABBCCDDEEFF`

Success response normalize về:

- `AA:BB:CC:DD:EE:FF`

### Live production đã được deploy

Đã deploy và verify production cho:

- `backend/app.py`
- `backend/utils.py`
- `backend/PUBLIC_API.md`
- một số template docs liên quan

Đã verify read-only endpoint trên live cho:

- `/api/public/device/by-mac`
- `/api/public/device/online-status`

với MAC dạng dash và compact.

## Những chỗ dễ nhầm

1. `README` cũ từng ghi `pm2 restart printagent-server`; production thật là `systemd printagent`.
2. Một số script trong `scripts/deploy/` vẫn còn path legacy như `server/` hoặc target process cũ.
3. Nhiều docs cũ từng gọi agent là `app/` và backend là `server/`; code hiện tại là `agent/` và `backend/`.
4. Không phải mọi script deploy trong repo đều an toàn để chạy nguyên xi.

## Nếu quay lại sau một thời gian

Đọc theo thứ tự này:

1. `README.md`
2. `backend/PUBLIC_API.md`
3. `docs/ENDPOINT.md`
4. `docs/AGENTS.md`
5. `backend/README.md`

Sau đó kiểm tra production:

```bash
systemctl status printagent --no-pager
ss -ltnp | grep 8005
```

## Các file hay phải động tới khi có thay đổi API

- `backend/app.py`
- `backend/utils.py`
- `backend/PUBLIC_API.md`
- `backend/templates/_app_scripts.html`
- `backend/templates/base.html`

## Nguyên tắc để tránh drift docs

- đổi public API: sửa `backend/PUBLIC_API.md` trước
- đổi deploy reality: sửa `README.md` và file này ngay
- đổi polling/control flow: sửa `docs/AGENTS.md` và `docs/ENDPOINT.md`
