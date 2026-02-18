#!/usr/bin/env bash
set -euo pipefail

# Modify PostgreSQL schema for lead -> LAN -> agent identity model.
# Usage:
#   ./migrate_lan_agent.sh
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

echo "[1/4] Adding lan_uid/agent_uid columns to timelapse tables..."
psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" <<'SQL'
ALTER TABLE "CounterInfor" ADD COLUMN IF NOT EXISTS lan_uid VARCHAR(128) DEFAULT 'legacy-lan';
ALTER TABLE "CounterInfor" ADD COLUMN IF NOT EXISTS agent_uid VARCHAR(128) DEFAULT 'legacy-agent';
ALTER TABLE "StatusInfor" ADD COLUMN IF NOT EXISTS lan_uid VARCHAR(128) DEFAULT 'legacy-lan';
ALTER TABLE "StatusInfor" ADD COLUMN IF NOT EXISTS agent_uid VARCHAR(128) DEFAULT 'legacy-agent';
SQL

echo "[2/4] Creating LanSite and AgentNode tables..."
psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" <<'SQL'
CREATE TABLE IF NOT EXISTS "LanSite" (
  id SERIAL PRIMARY KEY,
  lead VARCHAR(64) NOT NULL,
  lan_uid VARCHAR(128) NOT NULL,
  lan_name VARCHAR(255) DEFAULT '',
  subnet_cidr VARCHAR(64) DEFAULT '',
  gateway_ip VARCHAR(64) DEFAULT '',
  gateway_mac VARCHAR(64) DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS "AgentNode" (
  id SERIAL PRIMARY KEY,
  lead VARCHAR(64) NOT NULL,
  lan_uid VARCHAR(128) NOT NULL,
  agent_uid VARCHAR(128) NOT NULL,
  hostname VARCHAR(255) DEFAULT '',
  local_ip VARCHAR(64) DEFAULT '',
  local_mac VARCHAR(64) DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ DEFAULT NOW()
);
SQL

echo "[3/4] Creating indexes and unique constraints..."
psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" <<'SQL'
CREATE INDEX IF NOT EXISTS idx_counter_lan_uid ON "CounterInfor"(lan_uid);
CREATE INDEX IF NOT EXISTS idx_counter_agent_uid ON "CounterInfor"(agent_uid);
CREATE INDEX IF NOT EXISTS idx_status_lan_uid ON "StatusInfor"(lan_uid);
CREATE INDEX IF NOT EXISTS idx_status_agent_uid ON "StatusInfor"(agent_uid);

CREATE INDEX IF NOT EXISTS idx_lansite_lead_lan ON "LanSite"(lead, lan_uid);
CREATE INDEX IF NOT EXISTS idx_agentnode_lead_lan_agent ON "AgentNode"(lead, lan_uid, agent_uid);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'uq_lansite_lead_lan'
  ) THEN
    ALTER TABLE "LanSite" ADD CONSTRAINT uq_lansite_lead_lan UNIQUE (lead, lan_uid);
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'uq_agentnode_lead_lan_agent'
  ) THEN
    ALTER TABLE "AgentNode" ADD CONSTRAINT uq_agentnode_lead_lan_agent UNIQUE (lead, lan_uid, agent_uid);
  END IF;
END $$;
SQL

echo "[4/4] Done."
echo "Schema migration completed for DB ${DB_NAME}."
