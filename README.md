# GoPrinx / PrintAgent

Há»‡ thá»‘ng quáº£n lÃ½ mÃ¡y Ricoh gá»“m 3 pháº§n:

- `agent/`: agent cháº¡y trong LAN, scan mÃ¡y, polling dá»¯ liá»‡u, nháº­n lá»‡nh lock/unlock vÃ  FTP queue
- `backend/`: Flask server + PostgreSQL, nháº­n polling, render portal quáº£n trá»‹, public API
- `app-gox/`: frontend React/Vite cho portal ngÆ°á»i dÃ¹ng

## Tráº¡ng thÃ¡i hiá»‡n táº¡i

Snapshot nÃ y pháº£n Ã¡nh tráº¡ng thÃ¡i repo vÃ  production Ä‘Ã£ kiá»ƒm tra ngÃ y `2026-04-08`.

- Public API production: `https://agentapi.quanlymay.com`
- Frontend production: `https://app.quanlymay.com`
- Backend production cháº¡y trá»±c tiáº¿p táº¡i `/opt/printagent/`
- Service tháº­t trÃªn VPS lÃ  `systemd`: `systemctl restart printagent`
- Nginx proxy `agentapi.quanlymay.com` vÃ o `127.0.0.1:8005`
- Trang docs public render tá»« file `backend/PUBLIC_API.md` qua route `/api-docs`

## Äiá»u quan trá»ng cáº§n nhá»› khi quay láº¡i

1. Repo hiá»‡n dÃ¹ng `agent/` vÃ  `backend/`. Nhiá»u docs cÅ© váº«n nháº¯c `app/` vÃ  `server/`; coi Ä‘Ã³ lÃ  legacy.
2. Production khÃ´ng dÃ¹ng `pm2 restart printagent-server` cho backend nÃ y ná»¯a. DÃ¹ng `systemctl restart printagent`.
3. Device control public dÃ¹ng `mac_id`, khÃ´ng cÃ²n dÃ¹ng `printer_id` lÃ m contract chÃ­nh.
4. `POST /api/devices/<mac_id>/lock|unlock` vÃ  `PATCH /api/devices/<mac_id>/enable` khÃ´ng cÃ²n yÃªu cáº§u `auth_user` / `auth_password` trong request body.
5. Server hiá»‡n nháº­n `mac_id` theo 3 dáº¡ng:
   - `AA:BB:CC:DD:EE:FF`
   - `AA-BB-CC-DD-EE-FF`
   - `AABBCCDDEEFF`

## NÃªn Ä‘á»c gÃ¬ trÆ°á»›c

- `README.md`: overview + production reality
- `backend/PUBLIC_API.md`: contract public API chuáº©n
- `docs/ENDPOINT.md`: báº£n Ä‘á»“ endpoint ná»™i bá»™
- `docs/AGENTS.md`: agent runtime vÃ  cáº¥u hÃ¬nh
- `docs/GEMINI.md`: ghi chÃº handover / memory khi quay láº¡i dá»± Ã¡n
- `backend/README.md`: runbook riÃªng cho backend

## Cáº¥u trÃºc repo

```text
printagent/
â”œâ”€ agent/                  Agent Windows + local web UI
â”œâ”€ backend/                Flask server, templates, SQLAlchemy models
â”œâ”€ app-gox/                React/Vite frontend
â”œâ”€ docs/                   Handover docs, endpoint map, test plans
â”œâ”€ scripts/deploy/         CÃ¡c script deploy; cÃ³ cáº£ script current láº«n legacy
â”œâ”€ storage/                Dá»¯ liá»‡u cá»¥c bá»™/dev
â””â”€ dist/                   Output build agent exe
```

## Cháº¡y local

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

Máº·c Ä‘á»‹nh backend Ä‘á»c `.env` tá»« thÆ° má»¥c hiá»‡n táº¡i hoáº·c tá»« `backend/.env`.

### Agent EXE

Build:

```powershell
.\build_agent_exe.ps1
```

Deploy:

- `scripts/deploy/deploy_agent_exe.py`
- Upload `dist/printagent.exe` lÃªn `/opt/printagent/static/releases/printagent.exe`
- Upload manifest tá»« `backend/storage/releases/agent_release.json`

## CÃ¡c luá»“ng chÃ­nh

### Polling

1. Agent scan LAN, nháº­n diá»‡n mÃ¡y Ricoh
2. Agent thu `counter`, `status`, `device info`
3. Agent gá»­i `POST /api/polling`
4. Backend upsert dá»¯ liá»‡u latest vÃ o `DeviceInfor` vÃ  lÆ°u history vÃ o `CounterInfor`, `StatusInfor`

### Device control

1. Client gá»i `POST /api/devices/<mac_id>/unlock` hoáº·c `lock`
2. Backend queue `PrinterControlCommand`
3. Agent láº¥y lá»‡nh qua polling controls
4. Agent thao tÃ¡c lÃªn mÃ¡y Ricoh
5. Backend nháº­n result vÃ  tráº£ `200`, `409`, hoáº·c `504`

### FTP queue

1. Client gá»i `POST /api/agents/<agent_id>/ftp-sites`
2. Backend queue `FtpControlCommand`
3. Agent láº¥y queue qua polling
4. Agent tá»± suy ra FTP runtime ná»™i bá»™ tá»« `mac_id + scan_path`, rá»“i apply scan destination

## CÃ¡c file Ä‘Ã¡ng tin cáº­y nháº¥t

- Route thá»±c táº¿: `backend/app.py`
- Normalize MAC/IP vÃ  helper: `backend/utils.py`
- Public API contract: `backend/PUBLIC_API.md`
- Agent runtime config: `agent/config.py`
- Polling control loop: `agent/services/polling_bridge.py`

## CÃ¡c báº«y tÃ i liá»‡u cÅ©

- TÃ i liá»‡u cÅ© cÃ³ thá»ƒ nháº¯c:
  - `server/` thay vÃ¬ `backend/`
  - `app/` thay vÃ¬ `agent/`
  - WebSocket control flow cÅ©
  - `pm2 restart printagent-server`
  - `/api/printer/<id>/lock`
- CÃ¡c ná»™i dung Ä‘Ã³ khÃ´ng cÃ²n lÃ  nguá»“n sá»± tháº­t chÃ­nh.

## Gá»£i Ã½ khi tiáº¿p tá»¥c phÃ¡t triá»ƒn

- Náº¿u thay public API, sá»­a `backend/PUBLIC_API.md` trÆ°á»›c, rá»“i má»›i sá»­a docs cÃ²n láº¡i.
- Náº¿u thay polling/control flow, sá»­a `docs/AGENTS.md` vÃ  `docs/ENDPOINT.md`.
- Náº¿u thay deploy production, cáº­p nháº­t ngay `README.md` vÃ  `docs/GEMINI.md`.
