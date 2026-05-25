# Test Plan

This is the current high-level test plan for the repo as of `2026-04-08`.

## 1. Agent

- `TC-AG-01`: start agent in `web` mode and confirm local UI opens on port `9173`
- `TC-AG-02`: start agent in `service` mode and confirm periodic polling runs
- `TC-AG-03`: verify subnet scan discovers Ricoh devices with `mac_address`
- `TC-AG-04`: verify agent can post polling payload to backend
- `TC-AG-05`: verify agent receives and applies lock/unlock commands from polling queue
- `TC-AG-06`: verify agent receives and applies FTP queue commands
- `TC-AG-07`: verify scan-upload worker skips already uploaded files

## 2. Backend

- `TC-BE-01`: `POST /api/polling` stores latest state and history correctly
- `TC-BE-02`: `GET /api/devices` returns deduped device rows
- `TC-BE-03`: `POST /api/devices/<mac_id>/unlock` queues a command and waits for result
- `TC-BE-04`: `POST /api/devices/<mac_id>/lock` returns `409` on agent-side failure
- `TC-BE-05`: `PATCH /api/devices/<mac_id>/enable` still works as legacy alias
- `TC-BE-06`: MAC normalization accepts colon, dash, and compact formats
- `TC-BE-07`: `POST /api/agents/<agent_id>/ftp-sites` validates `mac_id` and queues correctly

## 3. Public API

- `TC-PUB-01`: `GET /api/public/device/by-mac?mac_id=AA:BB:...`
- `TC-PUB-02`: `GET /api/public/device/by-mac?mac_id=AA-BB-...`
- `TC-PUB-03`: `GET /api/public/device/by-mac?mac_id=AABB...`
- `TC-PUB-04`: `GET /api/public/device/online-status` returns normalized `mac_id`
- `TC-PUB-05`: invalid MAC format returns `400`
- `TC-PUB-06`: unknown MAC returns `404` where documented

## 4. Frontend / Portal

- `TC-FE-01`: login returns `workspaceIds` and workspace picker works
- `TC-FE-02`: devices page can trigger enable/disable through `/api/devices/<mac_id>/enable`
- `TC-FE-03`: agents page can queue FTP create/update/delete
- `TC-FE-04`: API docs page `/api-docs` renders the latest `PUBLIC_API.md`
- `TC-FE-05`: tasks/workspaces/locations/users CRUD pages call the correct backend APIs

## 5. Production verification

- `TC-PRD-01`: `systemctl status printagent --no-pager` is `active`
- `TC-PRD-02`: nginx still proxies `agentapi.quanlymay.com` to `127.0.0.1:8005`
- `TC-PRD-03`: public read-only endpoint works after deploy
- `TC-PRD-04`: backend restart does not break `/api-docs`

## 6. Recommended regression set before release

- device control via `mac_id`
- public by-mac lookup with all three MAC formats
- online-status lookup with all three MAC formats
- FTP queue create with valid `mac_id`
- `/api/polling` ingest from a real agent
