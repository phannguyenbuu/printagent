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

## 7) Agent machine export for CRM

- Method: `GET`
- Path: `/api/public/agent-machines`
- Query params (required):
  - `lead`
  - `agent_uid`

CRM partners use this endpoint to read the machines that belong to a PC agent (Tier 2). Each machine entry contains the lan/fingerprint metadata that already exists inside `DeviceInfor`, `LanSite`, and the new `NetworkInfo` table, plus counter, status, toner, alert, feature, and lock/unlock history derived from polling.

Example response:
```json
{
  "ok": true,
  "lead": "default",
  "agent_uid": "agent-pc-01",
  "agent": {
    "hostname": "PC-01",
    "local_ip": "192.168.1.10",
    "local_mac": "11:22:33:44:55:66"
  },
  "count": 2,
  "machines": [
    {
      "lead": "default",
      "lan_uid": "lanf-33ef2446897e0a57",
      "lan_name": "Factory A",
      "fingerprint_signature": "lead=default|subnet=192.168.1.0/24|gateway_ip=192.168.1.1|gateway_mac=AA:BB:CC:DD:EE:FF",
      "network": {
        "network_id": "net-001",
        "network_name": "Factory A LAN",
        "office_name": "Factory Floor",
        "real_address": "123 Factory Rd, District 1"
      },
      "agent_uid": "agent-pc-01",
      "printer_name": "Aficio MP 9002",
      "mac_id": "00:26:73:7D:78:F9",
      "ip": "192.168.1.224",
      "counter_total": 3653272,
      "counter_summary": {
        "copier_bw": 238346,
        "printer_bw": 316916,
        "fax_bw": 0
      },
      "status": "Status OK",
      "alert": "Energy Saver Mode",
      "toner": {
        "state": "Status OK"
      },
      "auto_alert": {
        "severity": "warning",
        "message": "Black toner is low",
        "status": "pending",
        "triggered_at": "2026-03-09T01:02:03+00:00",
        "resolved_at": ""
      },
      "features": [
        {
          "feature": "address_book",
          "enabled": true,
          "metadata": {},
          "last_seen_at": "2026-03-09T00:00:00+00:00"
        }
      ],
      "lock_history": [
        {
          "action": "lock",
          "reason": "Service window",
          "source": "lead",
          "event_at": "2026-03-09T01:05:00+00:00",
          "metadata": {}
        }
      ],
      "last_counter_at": "2026-03-02T00:00:00+00:00",
      "last_status_at": "2026-03-02T00:00:00+00:00",
      "updated_at": "2026-03-02T00:00:00+00:00"
    }
  ]
}
```

## 8) List tasks

- Method: `GET`
- Path: `/api/tasks`
- Query params:
  - `lead` (required)
  - `agent_uid` (optional)
  - `mac_id` or `mac` (optional)
  - `status` (optional; one of `backlog`, `selected`, `in-progress`, `review`, `done`, `blocked`)
  - `assignee_id` (optional)

Returns all of the tasks created for that lead. Each task links back to `UserAccount` roles (worker, leader, admin, account, customer) and reuses the device counters and status tracked inside `DeviceInfor`.

## 9) Create a task

- Method: `POST`
- Path: `/api/tasks`
- Headers:
  - `X-Lead-Token: <token>` (same lead token as `/api/polling`)
- Payload:
  ```json
  {
    "lead": "default",
    "lan_uid": "lanf-33ef2446897e0a57",
    "agent_uid": "agent-pc-01",
    "network_id": "net-001",
    "mac_id": "00:26:73:7D:78:F9",
    "title": "Check paper tray",
    "description": "Tray 1 keeps emptying",
    "status": "backlog",
    "priority": "high",
    "reporter_id": 42,
    "assignee_id": 7,
    "customer_id": 5
  }
  ```

The server assigns a `task_key`, stores the task in `Task`, and links it to the reporting worker (`reporter_id`), assignee, and customer accounts.

## 10) Update a task

- Method: `PATCH`
- Path: `/api/tasks/<task_id>`
- Headers:
  - `X-Lead-Token: <token>`
- Payload fields are optional; only include the fields you want to change. Status transitions are limited to Jira-like values (`backlog`, `selected`, `in-progress`, `review`, `done`, `blocked`). Provide `status_updated_at` or `completed_at` timestamps when relevant.

All task activity materializes in `Task`, while role metadata lives in `UserAccount` (worker, leader, admin, account, customer). The `DeviceFeatureFlag`, `DeviceLockHistory`, and `MachineAlert` tables hold the supplementary machine features mentioned earlier (address book, lock/unlock history, automated alerts).

## 11) Workspaces CRUD
- **List:** `GET /api/workspaces` (Params: `name`, `address`, `date_from`, `date_to`)
- **Create:** `POST /api/workspaces` (Body: `id`, `name`, `logo`, `color`, `address`)
- **Update:** `PATCH /api/workspaces/<ws_id>` (Body: `name`, `logo`, `color`, `address`)
- **Delete:** `DELETE /api/workspaces/<ws_id>`

## 12) Locations CRUD
- **List:** `GET /api/locations` (Params: `name`, `workspace_id`, `date_from`, `date_to`)
- **Create:** `POST /api/locations` (Body: `id`, `name`, `address`, `phone`, `machine_count`, `workspace_id`)
- **Update:** `PATCH /api/locations/<loc_id>` (Body: `name`, `address`, `phone`, `machine_count`, `workspace_id`)
- **Delete:** `DELETE /api/locations/<loc_id>`

## 13) Materials CRUD
- **List:** `GET /api/materials` (Params: `name`, `repair_id`, `date_from`, `date_to`)
- **Create:** `POST /api/materials` (Body: `id`, `repair_request_id`, `name`, `quantity`, `unit_price`, `total_price`)
- **Update:** `PATCH /api/materials/<mat_id>` (Body: `repair_request_id`, `name`, `quantity`, `unit_price`, `total_price`)
- **Delete:** `DELETE /api/materials/<mat_id>`

## 14) Users CRUD
- **List:** `GET /api/users` (Params: `lead`, `username`, `fullname`, `role`, `date_from`, `date_to`)
- **Create:** `POST /api/users` (Body: `lead`, `username`, `password`, `full_name`, `email`, `phone_number`, `role`, `is_active`, `notes`)
- **Update:** `PATCH /api/users/<user_id>` (Body: same as Create)
- **Delete:** `DELETE /api/users/<user_id>`

## 15) Networks/Companies CRUD
- **List:** `GET /api/networks` (Params: `lead`, `lan_uid`, `name`, `office`, `date_from`, `date_to`)
- **Create:** `POST /api/networks` (Body: `lead`, `lan_uid`, `network_id`, `network_name`, `office_name`, `real_address`, `notes`)
- **Update:** `PATCH /api/networks/<net_id>` (Body: same as Create)
- **Delete:** `DELETE /api/networks/<net_id>`

## 16) Leads CRUD
- **List:** `GET /api/leads/list` (Params: `name`, `date_from`, `date_to`)
- **Create:** `POST /api/leads` (Body: `id`, `name`, `email`, `phone`, `notes`)
- **Update:** `PATCH /api/leads/<lead_id>` (Body: `name`, `email`, `phone`, `notes`)
- **Delete:** `DELETE /api/leads/<lead_id>`


