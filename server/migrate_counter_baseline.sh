#!/usr/bin/env bash
set -euo pipefail

# Add CounterBaseline table for baseline + delta counter storage.
# Optional env:
#   DB_HOST (default localhost)
#   DB_PORT (default 5432)
#   DB_USER (default postgres)
#   DB_PASS (default myPass)
#   DB_NAME (default GoPrinx)

DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-postgres}"
DB_PASS="${DB_PASS:-myPass}"
DB_NAME="${DB_NAME:-GoPrinx}"

export PGPASSWORD="${DB_PASS}"

echo "[1/2] Creating CounterBaseline table..."
psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" <<'SQL'
CREATE TABLE IF NOT EXISTS "CounterBaseline" (
  id SERIAL PRIMARY KEY,
  lead VARCHAR(64) NOT NULL,
  lan_uid VARCHAR(128) NOT NULL DEFAULT 'legacy-lan',
  agent_uid VARCHAR(128) NOT NULL DEFAULT 'legacy-agent',
  printer_name VARCHAR(255) DEFAULT '',
  ip VARCHAR(64) NOT NULL,
  baseline_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  raw_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
SQL

echo "[2/2] Creating indexes and unique key..."
psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" <<'SQL'
CREATE INDEX IF NOT EXISTS idx_counterbaseline_lead ON "CounterBaseline"(lead);
CREATE INDEX IF NOT EXISTS idx_counterbaseline_lan_uid ON "CounterBaseline"(lan_uid);
CREATE INDEX IF NOT EXISTS idx_counterbaseline_agent_uid ON "CounterBaseline"(agent_uid);
CREATE INDEX IF NOT EXISTS idx_counterbaseline_ip ON "CounterBaseline"(ip);
CREATE INDEX IF NOT EXISTS idx_counterbaseline_baseline_timestamp ON "CounterBaseline"(baseline_timestamp);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'uq_counterbaseline_lead_lan_ip'
  ) THEN
    ALTER TABLE "CounterBaseline"
      ADD CONSTRAINT uq_counterbaseline_lead_lan_ip UNIQUE (lead, lan_uid, ip);
  END IF;
END $$;
SQL

echo "Done. CounterBaseline migration completed."
