# Project Memory

File nÃ y dÃ¹ng nhÆ° handover note Ä‘á»ƒ láº§n sau quay láº¡i dá»± Ã¡n nhanh hÆ¡n.

## Snapshot hiá»‡n táº¡i

NgÃ y kiá»ƒm tra gáº§n nháº¥t: `2026-04-08`

- API production: `https://agentapi.quanlymay.com`
- Frontend production: `https://app.quanlymay.com`
- Backend live files náº±m trá»±c tiáº¿p á»Ÿ `/opt/printagent/`
- Backend service tháº­t: `systemctl restart printagent`
- Local bind cá»§a backend production: `127.0.0.1:8005`
- Public docs page: `/api-docs`

## CÃ¡c thay Ä‘á»•i quan trá»ng gáº§n Ä‘Ã¢y

### Device control contract

ÄÃ£ chuyá»ƒn contract public sang:

- `POST /api/devices/<mac_id>/unlock`
- `POST /api/devices/<mac_id>/lock`
- `PATCH /api/devices/<mac_id>/enable`

KhÃ´ng cÃ²n dÃ¹ng `printer_id` nhÆ° contract chÃ­nh cho client ngoÃ i.

### Credentials

Public request lock/unlock khÃ´ng cÃ²n yÃªu cáº§u:

- `auth_user`
- `auth_password`

Agent/backend váº«n cÃ³ thá»ƒ giá»¯ credential ná»™i bá»™ Ä‘á»ƒ thá»±c thi login lÃªn Ricoh khi cáº§n.

### MAC normalization

Server hiá»‡n accept cáº£ 3 dáº¡ng:

- `AA:BB:CC:DD:EE:FF`
- `AA-BB-CC-DD-EE-FF`
- `AABBCCDDEEFF`

Success response normalize vá»:

- `AA:BB:CC:DD:EE:FF`

### Live production Ä‘Ã£ Ä‘Æ°á»£c deploy

ÄÃ£ deploy vÃ  verify production cho:

- `backend/app.py`
- `backend/utils.py`
- `backend/PUBLIC_API.md`
- má»™t sá»‘ template docs liÃªn quan

ÄÃ£ verify read-only endpoint trÃªn live cho:

- `/api/public/device/by-mac`
- `/api/public/device/online-status`

vá»›i MAC dáº¡ng dash vÃ  compact.

## Nhá»¯ng chá»— dá»… nháº§m

1. `README` cÅ© tá»«ng ghi `pm2 restart printagent-server`; production tháº­t lÃ  `systemd printagent`.
2. Cac script deploy legacy tro `server/`, `app-gox/dist`, hoac `pm2` da duoc don khoi repo.
3. Nhiá»u docs cÅ© tá»«ng gá»i agent lÃ  `app/` vÃ  backend lÃ  `server/`; code hiá»‡n táº¡i lÃ  `agent/` vÃ  `backend/`.
4. KhÃ´ng pháº£i má»i script deploy trong repo Ä‘á»u an toÃ n Ä‘á»ƒ cháº¡y nguyÃªn xi.

## Náº¿u quay láº¡i sau má»™t thá»i gian

Äá»c theo thá»© tá»± nÃ y:

1. `README.md`
2. `backend/PUBLIC_API.md`
3. `docs/ENDPOINT.md`
4. `docs/AGENTS.md`
5. `backend/README.md`

Sau Ä‘Ã³ kiá»ƒm tra production:

```bash
systemctl status printagent --no-pager
ss -ltnp | grep 8005
```

## CÃ¡c file hay pháº£i Ä‘á»™ng tá»›i khi cÃ³ thay Ä‘á»•i API

- `backend/app.py`
- `backend/utils.py`
- `backend/PUBLIC_API.md`
- `backend/templates/_app_scripts.html`
- `backend/templates/base.html`

## NguyÃªn táº¯c Ä‘á»ƒ trÃ¡nh drift docs

- Ä‘á»•i public API: sá»­a `backend/PUBLIC_API.md` trÆ°á»›c
- Ä‘á»•i deploy reality: sá»­a `README.md` vÃ  file nÃ y ngay
- Ä‘á»•i polling/control flow: sá»­a `docs/AGENTS.md` vÃ  `docs/ENDPOINT.md`
