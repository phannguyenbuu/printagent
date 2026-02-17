# GoPrinx Polling Server (Tier 3)

This Flask service receives polling data from agents every 60 seconds and stores it in PostgreSQL.

## Architecture (3 tiers)
- Tier 1: PC agent talks to Ricoh device, collects `counter` + `status`.
- Tier 2: Mini server on PC handles local methods/distribution.
- Tier 3: This server authenticates `lead`, stores to PostgreSQL, and supports long-term analytics.

## PostgreSQL
- User: `postgres`
- Password: `myPass`
- Database: `GoPrinx`
- Tables: `CounterInfor`, `StatusInfor`
- Extra management fields: `lead`, `timestamp`

## Quick setup on VPS (Windows)
1. Install PostgreSQL and ensure `psql` is available in `PATH`.
2. Run:
   - `server\setup_vps_postgres.bat`
3. Start server:
   - `set DATABASE_URL=postgresql+psycopg2://postgres:myPass@localhost:5432/GoPrinx`
   - `set LEAD_KEYS=default:change-me`
   - `python app.py`

## API
### Health
- `GET /health`

### Polling ingest
- `POST /api/polling`
- Header:
  - `X-Lead-Token: <token>`
- JSON body (same shape as current agent payload):
```json
{
  "lead": "default",
  "printer_name": "Ricoh 7503",
  "ip": "192.168.1.222",
  "timestamp": "2026-02-17T14:43:05.041902+00:00",
  "counter_data": {
    "total": "555262",
    "copier_bw": "238346",
    "printer_bw": "316916",
    "a3_dlt": "73095",
    "duplex": "152865"
  },
  "status_data": {
    "system_status": "OK",
    "printer_alerts": "Energy Saver Mode",
    "tray_1_status": "Almost Out of Paper"
  }
}
```

## Notes
- Default lead mapping is controlled by env `LEAD_KEYS` in format:
  - `leadA:tokenA,leadB:tokenB`
- Agent polling interval remains 60 seconds on Tier 1/Tier 2 side.
