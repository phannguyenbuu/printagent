#!/usr/bin/env bash
set -euo pipefail

# Seed a default lead ("default") into PostgreSQL for GoPrinx.
# Usage:
#   ./seed_default_lead.sh
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

echo "[1/2] Seeding lead='default' into LanSite and AgentNode (if missing)..."
psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" <<'SQL'
INSERT INTO "LanSite" (lead, lan_uid, lan_name, subnet_cidr, gateway_ip, gateway_mac)
SELECT 'default', 'seed-lan-default', 'Default LAN', '', '', ''
WHERE NOT EXISTS (
  SELECT 1 FROM "LanSite" WHERE lead = 'default' AND lan_uid = 'seed-lan-default'
);

INSERT INTO "AgentNode" (lead, lan_uid, agent_uid, hostname, local_ip, local_mac)
SELECT 'default', 'seed-lan-default', 'seed-agent-default', 'seed-node', '', ''
WHERE NOT EXISTS (
  SELECT 1
  FROM "AgentNode"
  WHERE lead = 'default' AND lan_uid = 'seed-lan-default' AND agent_uid = 'seed-agent-default'
);
SQL

echo "[2/2] Current leads in DB:"
psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -c \
"SELECT DISTINCT lead FROM (
  SELECT lead FROM \"LanSite\"
  UNION ALL
  SELECT lead FROM \"AgentNode\"
  UNION ALL
  SELECT lead FROM \"CounterInfor\"
  UNION ALL
  SELECT lead FROM \"StatusInfor\"
) s
WHERE lead IS NOT NULL AND btrim(lead) <> ''
ORDER BY lead;"

echo "Done."
