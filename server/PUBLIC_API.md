# Public API for CRM

Base URL (production):
- `https://agentapi.quanlymay.com`

These endpoints are read-only and return JSON.

## 1) Machine list
- Method: `GET`
- Path: `/machinelist/`
- Query params (optional):
  - `lead`: filter by lead
  - `lan_uid`: filter by LAN id

Example:
```bash
curl -s "https://agentapi.quanlymay.com/machinelist/?lead=default"
```

Response:
```json
{
  "ok": true,
  "count": 2,
  "machines": [
    {
      "lead": "default",
      "lan_uid": "lanf-33ef2446897e0a57",
      "mac_id": "00:26:73:7D:78:F9",
      "agent_uid": "agent-pc-01",
      "printer_name": "Aficio MP 9002",
      "ip": "192.168.1.224",
      "counter_total": 3653272,
      "system_status": "Status OK",
      "toner_black": {
        "state": "Status OK"
      },
      "created_at": "2026-03-01T16:00:00+00:00",
      "updated_at": "2026-03-02T00:00:00+00:00",
      "last_counter_at": "2026-03-02T00:00:00+00:00",
      "last_status_at": "2026-03-02T00:00:00+00:00"
    }
  ]
}
```

## 2) Network list
- Method: `GET`
- Path: `/networklist/`
- Query params (optional):
  - `lead`: filter by lead

Example:
```bash
curl -s "https://agentapi.quanlymay.com/networklist/?lead=default"
```

Response:
```json
{
  "ok": true,
  "count": 1,
  "networks": [
    {
      "lead": "default",
      "lan_uid": "lanf-33ef2446897e0a57",
      "machine_count": 2,
      "last_seen_at": "2026-03-02T00:00:00+00:00"
    }
  ]
}
```

## 3) Existing infor list (kept as-is)
- Method: `GET`
- Path: `/api/infor/list`
- Query params (optional):
  - `lead`: filter by lead

Example:
```bash
curl -s "https://agentapi.quanlymay.com/api/infor/list?lead=default"
```

Notes:
- The `counter_data` and `status_data` fields are JSON objects.
- `mac_id` is normalized in `AA:BB:CC:DD:EE:FF` format.

## 4) Get device infor by MAC ID
- Method: `GET`
- Path: `/api/public/device/by-mac`
- Query params (required):
  - `mac_id` (or `mac`)

Example:
```bash
curl -s "https://agentapi.quanlymay.com/api/public/device/by-mac?mac_id=00:26:73:7D:78:F9"
```

Response:
```json
{
  "ok": true,
  "mac_id": "00:26:73:7D:78:F9",
  "lead": "default",
  "lan_uid": "lanf-33ef2446897e0a57",
  "agent_uid": "agent-pc-01",
  "printer_name": "Aficio MP 9002",
  "ip": "192.168.1.224",
  "counter": {
    "total": "3653272"
  },
  "status": {
    "system_status": "Status OK"
  },
  "last_counter_at": "2026-03-02T00:00:00+00:00",
  "last_status_at": "2026-03-02T00:00:00+00:00",
  "updated_at": "2026-03-02T00:00:00+00:00"
}
```

## 5) Get all machine infor by LAN UID
- Method: `GET`
- Path: `/api/public/network/by-lan`
- Query params (required):
  - `lan_uid`
- Query params (optional):
  - `lead`

Example:
```bash
curl -s "https://agentapi.quanlymay.com/api/public/network/by-lan?lan_uid=lanf-33ef2446897e0a57"
```

Response:
```json
{
  "ok": true,
  "lan_uid": "lanf-33ef2446897e0a57",
  "count": 2,
  "rows": [
    {
      "lead": "default",
      "lan_uid": "lanf-33ef2446897e0a57",
      "mac_id": "00:26:73:7D:78:F9",
      "agent_uid": "agent-pc-01",
      "printer_name": "Aficio MP 9002",
      "ip": "192.168.1.224",
      "counter": { "total": "3653272" },
      "status": { "system_status": "Status OK" },
      "last_counter_at": "2026-03-02T00:00:00+00:00",
      "last_status_at": "2026-03-02T00:00:00+00:00",
      "created_at": "2026-03-01T16:00:00+00:00",
      "updated_at": "2026-03-02T00:00:00+00:00"
    }
  ]
}
```

## 6) Get all data (all LANs, all machines)
- Method: `GET`
- Path: `/all/`
- Query params (optional):
  - `lead`
  - `lan_uid`

Example:
```bash
curl -s "https://agentapi.quanlymay.com/all/"
```

Response:
```json
{
  "ok": true,
  "count": 4,
  "rows": [
    {
      "lead": "default",
      "lan_uid": "lanf-33ef2446897e0a57",
      "machine_uid": "00:26:73:7D:78:F9",
      "mac_id": "00:26:73:7D:78:F9",
      "agent_uid": "agent-pc-01",
      "printer_name": "Aficio MP 9002",
      "ip": "192.168.1.224",
      "counter": { "total": "3653272" },
      "status": { "system_status": "Status OK" },
      "last_counter_at": "2026-03-02T00:00:00+00:00",
      "last_status_at": "2026-03-02T00:00:00+00:00",
      "created_at": "2026-03-01T16:00:00+00:00",
      "updated_at": "2026-03-02T00:00:00+00:00"
    }
  ]
}
```
