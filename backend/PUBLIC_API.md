# Public API for CRM

Base URL (production):
- `https://agentapi.quanlymay.com`

These endpoints are read-only and return JSON.

Note:
- `POST /api/login` and `POST /api/login/google` now include `workspaceIds` in the returned user object.
- User-to-workspace membership is stored in the `UserWorkspace` table.
- Clients no longer need to send any tenant or scope parameter to the API. Protected endpoints resolve request scope from `X-API-Token`; internal CRUD endpoints fall back to the default server scope when needed.
- Table-backed GET/list responses expose audit fields as `created_at`, `updated_at`, and camelCase aliases `createAt`, `updateAt`.

## 1) Machine list
- Method: `GET`
- Path: `/machinelist/`
- Query params (optional):
  - `lan_uid`: filter by LAN id

Example:
```bash
curl -s "https://agentapi.quanlymay.com/machinelist/"
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

Example:
```bash
curl -s "https://agentapi.quanlymay.com/networklist/"
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

Example:
```bash
curl -s "https://agentapi.quanlymay.com/api/infor/list"
```

Notes:
- The `counter_data` and `status_data` fields are JSON objects.
- `mac_id` is normalized in `AA:BB:CC:DD:EE:FF` format.

## 4) Get device infor by MAC ID
- Method: `GET`
- Path: `/api/public/device/by-mac`
- Query params (required):
  - `mac_id` (or `mac`) – MAC address, any format: `00:26:73:7D:78:F9`, `00-26-73-7D-78-F9`, or `0026737D78F9`

Example:
```bash
curl -s "https://agentapi.quanlymay.com/api/public/device/by-mac?mac_id=0026737D78F9"
```

Notes:
- Success responses always normalize `mac_id` to `AA:BB:CC:DD:EE:FF`.
- Invalid MAC format returns `400`.
- Unknown device returns `404`.

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

## 5) Check online status by MAC ID
- Method: `GET`
- Path: `/api/public/device/online-status`
- Query params:
  - `mac_id` (required) – MAC address, any format: `00:26:73:7D:78:F9`, `00-26-73-7D-78-F9`, or `0026737D78F9`
  - `stale_seconds` (optional) – seconds without polling before considered offline (default: `300`)

Example:
```bash
curl -s "https://agentapi.quanlymay.com/api/public/device/online-status?mac_id=00-26-73-7D-78-F9"
```

Response (online):
```json
{
  "ok": true,
  "mac_id": "00:26:73:7D:78:F9",
  "is_online": true,
  "printer_name": "Aficio MP 9002",
  "ip": "192.168.1.224",
  "lead": "default",
  "lan_uid": "lanf-33ef2446897e0a57",
  "last_seen_at": "2026-03-21T05:00:00+00:00",
  "seconds_since_seen": 42,
  "stale_threshold_seconds": 300,
  "online_source": "polling",
  "is_online_by_polling": true,
  "is_online_by_flag": true
}
```

Response (offline):
```json
{
  "ok": true,
  "mac_id": "00:26:73:7D:78:F9",
  "is_online": false,
  "printer_name": "Aficio MP 9002",
  "ip": "192.168.1.224",
  "lead": "default",
  "lan_uid": "lanf-33ef2446897e0a57",
  "last_seen_at": "2026-03-21T04:00:00+00:00",
  "seconds_since_seen": 3642,
  "stale_threshold_seconds": 300,
  "online_source": "none",
  "is_online_by_polling": false,
  "is_online_by_flag": false
}
```

**Logic xác định online:**
- `is_online_by_polling = true` nếu `updated_at < 300s` (agent đang chạy và poll data)
- `is_online_by_flag = true` nếu `Printer.is_online = true` (set bởi hệ thống `_refresh_stale_offline`)
- `is_online = is_online_by_polling OR is_online_by_flag`
- `online_source`: `"polling"` | `"printer_flag"` | `"none"`

Response (not found):
```json
{ "ok": false, "error": "Device not found" }
```

## 6) Get all machine infor by LAN UID
- Method: `GET`
- Path: `/api/public/network/by-lan`
- Query params (required):
  - `lan_uid`

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

## 8) Get workspaces linked to a user
- Method: `GET`
- Path: `/api/user/workspaces`
- Query params (required):
  - `user_id`

Example:
```bash
curl -s "https://agentapi.quanlymay.com/api/user/workspaces?user_id=7"
```

Response:
```json
{
  "ok": true,
  "user_id": 7,
  "rows": [
    {
      "id": "ws-1",
      "name": "Công ty TNHH Gox Print",
      "logo": "🏭",
      "color": "#2196F3",
      "address": "123 Nguyễn Huệ, Q1, TP.HCM",
      "created_at": "2026-03-10"
    }
  ]
}
```

## 9) Get users linked to a workspace
- Method: `GET`
- Path: `/api/workspace/users`
- Query params (required):
  - `workspace_id`

Example:
```bash
curl -s "https://agentapi.quanlymay.com/api/workspace/users?workspace_id=ws-1"
```

Response:
```json
{
  "ok": true,
  "workspace_id": "ws-1",
  "rows": [
    {
      "id": 7,
      "lead": "default",
      "username": "tech1",
      "full_name": "Lê Minh Cường",
      "email": "tech1@kythuat.vn",
      "type": "tech",
      "role": "tech",
      "workspaceIds": ["ws-1", "ws-2", "ws-3"]
    }
  ]
}
```
- Path: `/api/public/agent-machines`
- Query params (required):
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

## 8) Ricoh machine lock/unlock

Use these endpoints to queue a lock or unlock command for a Ricoh device already known by the server. The backend pushes the command to the matching agent through polling, then waits for the agent result.

- List devices first: `GET /api/devices`
- Unlock a Ricoh machine: `POST /api/devices/<mac_id>/unlock`
- Lock a Ricoh machine: `POST /api/devices/<mac_id>/lock`
- Legacy alias kept for compatibility: `PATCH /api/devices/<mac_id>/enable` with body `{ "enabled": true|false }`

Notes:
- Use the `mac_id` value returned by `GET /api/devices`.
- The server accepts `mac_id` in these formats: `AA:BB:CC:DD:EE:FF`, `AA-BB-CC-DD-EE-FF`, or `AABBCCDDEEFF`.
- Success responses normalize `mac_id` to `AA:BB:CC:DD:EE:FF`.
- Success returns `200`.
- Agent-side failure returns `409`.
- Timeout waiting for the agent returns `504`.

Test commands:
```bash
curl -s "https://agentapi.quanlymay.com/api/devices"
```

```bash
curl -s -X POST "https://agentapi.quanlymay.com/api/devices/0026737D78F9/unlock"
```

```bash
curl -s -X POST "https://agentapi.quanlymay.com/api/devices/00-26-73-7D-78-F9/lock"
```

Example success response:
```json
{
  "ok": true,
  "id": 123,
  "mac_id": "00:26:73:7D:78:F9",
  "enabled": true,
  "action": "unlock",
  "changed_at": "2026-04-07T10:15:30+00:00",
  "command_id": 456
}
```

## 8A) Device scan-folder assignment

Use this endpoint when the client only knows the Ricoh machine MAC and wants the server to choose the correct Windows agent automatically.

- Discover target machines first: `GET /api/devices`
- Queue scan-folder create/update/delete: `POST /api/devices/<mac_id>/scan-folder`
- Legacy alias kept for compatibility: `POST /api/agents/<agent_id>/ftp-sites`

Notes:
- The server resolves the printer by `mac_id`, reads its `lead + lan_uid`, then picks an agent on the same LAN before queueing the command.
- When multiple same-LAN agents exist, the server prefers an online agent, then the most recently seen one.
- If the body also contains `mac_id`, it must match the path device.
- `create` normally sends `scan_path`; `update` and `delete` normally send `site_name`.
- `scan_path` can be a simple folder name or a full path on the chosen agent.
- If `scan_path` is a simple name, the agent creates the folder under its default scan root.
- `site_name`, `ftp_user`, `ftp_password`, and `port` remain compatibility fields; clients usually do not need them.
- If an explicit `port` is already used by another FTP site, the server returns `409`.
- If no explicit `port` is sent and the default port is busy, the server auto-picks the next free port and returns a `warning`.
- Commands are queued only. The chosen agent applies them on its next polling cycle.

Example create payload:
```json
{
  "action": "create",
  "scan_path": "scan_002673D3250B"
}
```

Queue create:
```bash
curl -s -X POST "https://agentapi.quanlymay.com/api/devices/00:26:73:D3:25:0B/scan-folder" \
  -H "Content-Type: application/json" \
  -d "{\"action\":\"create\",\"scan_path\":\"scan_002673D3250B\"}"
```

Queue update:
```bash
curl -s -X POST "https://agentapi.quanlymay.com/api/devices/002673D3250B/scan-folder" \
  -H "Content-Type: application/json" \
  -d "{\"action\":\"update\",\"site_name\":\"scan_002673D3250B\",\"scan_path\":\"C:/Scans/Ricoh-01\"}"
```

Queue delete:
```bash
curl -s -X POST "https://agentapi.quanlymay.com/api/devices/00-26-73-D3-25-0B/scan-folder" \
  -H "Content-Type: application/json" \
  -d "{\"action\":\"delete\",\"site_name\":\"scan_002673D3250B\"}"
```

Example success response:
```json
{
  "ok": true,
  "queued": true,
  "command_id": 123,
  "status": "pending",
  "action": "create",
  "lead": "default",
  "lan_uid": "lanf-33ef2446897e0a57",
  "agent_id": 35,
  "agent_uid": "tony",
  "agent_local_ip": "192.168.1.10",
  "agent_is_online": true,
  "mac_id": "00:26:73:D3:25:0B",
  "port": 2121,
  "scan_path": "scan_002673D3250B",
  "site_name": "scan_002673D3250B",
  "printer_name": "MP 6503",
  "printer_ip": "192.168.1.226",
  "printer_agent_uid": "tony",
  "warning": ""
}
```

Example validation error when no same-LAN agent exists:
```json
{
  "ok": false,
  "error": "No agent found on lan_uid lanf-33ef2446897e0a57 for printer 00:26:73:D3:25:0B",
  "mac_id": "00:26:73:D3:25:0B",
  "lan_uid": "lanf-33ef2446897e0a57",
  "available_agents": [
    {
      "id": 12,
      "agent_uid": "agent-pc-01",
      "lan_uid": "lanf-deadbeef",
      "local_ip": "192.168.5.10",
      "is_online": false
    }
  ]
}
```

## 8B) Legacy agent queue alias

If the client already knows the exact host agent, it can still call:

- `POST /api/agents/<agent_id>/ftp-sites`

The server keeps the same `action=create|update|delete` payload shape, still validates `lan_uid` for `create`, and now returns the same enriched response fields as the device-based route above.

## 9) List tasks

- Method: `GET`
- Path: `/api/tasks`
- Query params:
  - `agent_uid` (optional)
  - `mac_id` or `mac` (optional)
  - `status` (optional; one of `backlog`, `selected`, `in-progress`, `review`, `done`, `blocked`)
  - `assignee_id` (optional)

Returns the matching tasks. If `X-API-Token` is present, the server scopes the list to the account scope behind that token. Each task links back to `UserAccount` records and reuses the device counters and status tracked inside `DeviceInfor`.

## 10) Create a task

- Method: `POST`
- Path: `/api/tasks`
- Headers:
  - `X-API-Token: <token>` (same API token as `/api/polling`)
- Payload:
  ```json
  {
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

The server derives the task scope from `X-API-Token`, assigns a `task_key`, stores the task in `Task`, and links it to the reporting worker (`reporter_id`), assignee, and customer accounts.

## 11) Update a task

- Method: `PATCH`
- Path: `/api/tasks/<task_id>`
- Headers:
  - `X-API-Token: <token>`
- Payload:
  - All other fields are optional; only include the fields you want to change.
  - Status transitions are limited to Jira-like values (`backlog`, `selected`, `in-progress`, `review`, `done`, `blocked`).
  - Provide `status_updated_at` or `completed_at` timestamps when relevant.
  - The server resolves request scope from `X-API-Token`.

### Delete a task

- Method: `DELETE`
- Path: `/api/tasks/<task_id>`
- Headers:
  - `X-API-Token: <token>`

The server resolves request scope from `X-API-Token`.

Returns:

```json
{
  "ok": true,
  "id": 123
}
```

All task activity materializes in `Task`, while user assignment metadata lives in `UserAccount` together with workspace/location mappings. The `DeviceFeatureFlag`, `DeviceLockHistory`, and `MachineAlert` tables hold the supplementary machine features mentioned earlier (address book, lock/unlock history, automated alerts).

## 12) Workspaces CRUD
- **List:** `GET /api/workspaces` (Params: `name`, `address`, `date_from`, `date_to`)
- **Create:** `POST /api/workspaces` (Body: `id`, `name`, `logo`, `color`, `address`, `userIds`)
- **Update:** `PATCH /api/workspaces/<ws_id>` (Body: `name`, `logo`, `color`, `address`, `userIds`)
- **Delete:** `DELETE /api/workspaces/<ws_id>`
- Response rows include `userIds`, `userCount`, `locationIds`, and `locationCount`.

## 13) Locations CRUD
- **List:** `GET /api/locations` (Params: `name`, `workspace_id`, `date_from`, `date_to`)
- **Create:** `POST /api/locations` (Body: `id`, `name`, `address`, `room`, `phone`, `machine_count`, `workspace_id`)
- **Update:** `PATCH /api/locations/<loc_id>` (Body: `name`, `address`, `room`, `phone`, `machine_count`, `workspace_id`)
- **Delete:** `DELETE /api/locations/<loc_id>`
- Each location belongs to at most one workspace. `workspace_id` is validated on create/update.

## 14) Materials CRUD
- **List:** `GET /api/materials` (Params: `name`, `repair_id`, `date_from`, `date_to`)
- **Create:** `POST /api/materials` (Body: `id`, `repair_request_id`, `name`, `quantity`, `unit_price`, `total_price`)
- **Update:** `PATCH /api/materials/<mat_id>` (Body: `repair_request_id`, `name`, `quantity`, `unit_price`, `total_price`)
- **Delete:** `DELETE /api/materials/<mat_id>`

## 15) Users CRUD
- **List:** `GET /api/users` (Params: `username`, `fullname`, `type`, `role`, `date_from`, `date_to`)
- **Create:** `POST /api/users` (Body: `username`, `password`, `full_name`, `email`, `phone_number`, `type`, `workspaceIds`, `is_active`, `notes`)
- **Update:** `PATCH /api/users/<user_id>` (Body: same as Create)
- **Delete:** `DELETE /api/users/<user_id>`
- User `type` is normalized to one of `tech` or `support`. Legacy `role` input is still accepted as an alias and normalized to the same two values. Create requests inherit the default server scope when no internal scope is supplied.

## 16) Networks/Companies CRUD
- **List:** `GET /api/networks` (Params: `lan_uid`, `name`, `office`, `date_from`, `date_to`)
- **Create:** `POST /api/networks` (Body: `lan_uid`, `network_id`, `network_name`, `office_name`, `real_address`, `notes`)
- **Update:** `PATCH /api/networks/<net_id>` (Body: same as Create)
- **Delete:** `DELETE /api/networks/<net_id>`
- Create requests inherit the default server scope when no internal scope is supplied.

## UserWorkspace membership
- Membership between users and workspaces is stored in `UserWorkspace`.
- A user can belong to many workspaces, and a workspace can contain many users.
- Login endpoints return `workspaceIds` so the frontend can show the workspace picker.
- The read APIs below are the canonical lookup methods for the current membership model.
