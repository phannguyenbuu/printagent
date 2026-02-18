#!/usr/bin/env bash
set -euo pipefail

# Reset all GoPrinx data tables and restart identity counters.
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

echo "Resetting GoPrinx data in ${DB_NAME}..."
psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" <<'SQL'
TRUNCATE TABLE
  "CounterInfor",
  "StatusInfor",
  "CounterBaseline",
  "PrinterControlCommand",
  "PrinterOnlineLog",
  "PrinterEnableLog",
  "Printer",
  "AgentNode",
  "LanSite"
RESTART IDENTITY CASCADE;
SQL

echo "Done."
