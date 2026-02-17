# Flask Printer Agent

## Run

```powershell
cd d:\Projects\agent
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .[dev]
python -m app.main
```

Web UI (mac dinh):

- URL: `http://127.0.0.1:5000/dashboard`
- Tabs: Config, Device Manager, Counter Trend
- Dashboard now includes:
  - ENV runtime snapshot (loaded from `.env`)
  - Network printer config profile
  - Computer list, printer list, and many-to-many cross mapping
- Menu thao tac trong tab Device Manager bam sat `-test`: `1,3,4,5,6,7,8`

Flask runtime can be configured in `.env`:

```dotenv
FLASK_HOST=127.0.0.1
FLASK_PORT=5000
FLASK_DEBUG=false
```

Optional modes:

```powershell
python -m app.main --mode service
python -m app.main --mode test
```

## WebSocket Connection To Main Server

Preferred: configure in `.env`:

```dotenv
WS_URL=ws://main-server:9000/ws/agent
WS_TOKEN=
WS_AUTO_CONNECT=true
DATABASE_URL=sqlite:///storage/data/agent_config.db
WEBHOOK_MODE=listen
WEBHOOK_LISTEN_PATH=/api/update/receive-text
```

You can still configure in `config.yaml`:

```yaml
ws:
  url: "ws://main-server:9000/ws/agent"
  token: ""
  auto_connect: true
```

Control APIs:

- `GET /api/ws/status`
- `POST /api/ws/connect`
- `POST /api/ws/disconnect`
- `POST /api/ws/send` with JSON body `{ "event": "...", "payload": {} }`

## Auto Update From Main Server

Set in `.env`:

```dotenv
APP_VERSION=0.1.0
UPDATE_AUTO_APPLY=false
UPDATE_DEFAULT_COMMAND=git pull --ff-only
UPDATE_ALLOWED_PREFIX=git pull --ff-only
UPDATE_WEBHOOK_TOKEN=
```

Behavior:

- When WebSocket receives update text/JSON, Flask records update signal.
- If `UPDATE_AUTO_APPLY=true`, Flask runs update command automatically.
- Supported message examples from server:
  - JSON: `{"event":"update_available","payload":{"version":"0.1.1","command":"git pull --ff-only"}}`
  - Plain text: `UPDATE 0.1.1|git pull --ff-only`
  - Plain text command: `git pull --ff-only`

Update APIs:

- `GET /api/update/status`
- `POST /api/update/check` with body `{"version":"0.1.1","command":"git pull --ff-only"}`
- `POST /api/update/receive-text` with body `{"text":"UPDATE 0.1.1|git pull --ff-only"}`
  - Optional header: `X-Update-Token` if `UPDATE_WEBHOOK_TOKEN` is set.

## Notes

- Binary files in `printerauto/drivers` are untouched.
- This project ports the `printerdeamon/quanlymay` service flow to Python + Flask UI.
