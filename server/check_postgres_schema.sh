#!/usr/bin/env bash
set -euo pipefail

# Verify PostgreSQL schema for GoPrinx (root layout)
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

fail=0

check_table() {
  local table="$1"
  local exists
  exists="$(psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -tAc "SELECT to_regclass('public.\"${table}\"') IS NOT NULL;")"
  if [[ "$(echo "${exists}" | tr -d '[:space:]')" == "t" ]]; then
    echo "[OK] table ${table}"
  else
    echo "[FAIL] missing table ${table}"
    fail=1
  fi
}

check_column() {
  local table="$1"
  local column="$2"
  local exists
  exists="$(psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -tAc \
    "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='${table}' AND column_name='${column}');")"
  if [[ "$(echo "${exists}" | tr -d '[:space:]')" == "t" ]]; then
    echo "  [OK] ${table}.${column}"
  else
    echo "  [FAIL] missing ${table}.${column}"
    fail=1
  fi
}

check_unique() {
  local table="$1"
  local constraint="$2"
  local exists
  exists="$(psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -tAc \
    "SELECT EXISTS (SELECT 1 FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname='public' AND t.relname='${table}' AND c.conname='${constraint}');")"
  if [[ "$(echo "${exists}" | tr -d '[:space:]')" == "t" ]]; then
    echo "  [OK] constraint ${table}.${constraint}"
  else
    echo "  [FAIL] missing constraint ${table}.${constraint}"
    fail=1
  fi
}

echo "Checking connection..."
psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -c "SELECT current_database(), current_user;" >/dev/null
echo "[OK] connected to ${DB_NAME} as ${DB_USER}"

echo
echo "Checking tables..."
check_table "CounterInfor"
check_table "StatusInfor"
check_table "LanSite"
check_table "AgentNode"

echo
echo "Checking CounterInfor columns..."
for col in id lead lan_uid agent_uid timestamp printer_name ip total copier_bw printer_bw fax_bw send_tx_total_bw send_tx_total_color fax_transmission_total scanner_send_bw scanner_send_color coverage_copier_bw coverage_printer_bw coverage_fax_bw a3_dlt duplex raw_payload created_at; do
  check_column "CounterInfor" "${col}"
done

echo
echo "Checking StatusInfor columns..."
for col in id lead lan_uid agent_uid timestamp printer_name ip system_status printer_status printer_alerts copier_status copier_alerts scanner_status scanner_alerts toner_black tray_1_status tray_2_status tray_3_status bypass_tray_status other_info raw_payload created_at; do
  check_column "StatusInfor" "${col}"
done

echo
echo "Checking LanSite columns..."
for col in id lead lan_uid lan_name subnet_cidr gateway_ip gateway_mac created_at updated_at; do
  check_column "LanSite" "${col}"
done

echo
echo "Checking AgentNode columns..."
for col in id lead lan_uid agent_uid hostname local_ip local_mac created_at last_seen_at; do
  check_column "AgentNode" "${col}"
done

echo
echo "Checking unique constraints..."
check_unique "LanSite" "uq_lansite_lead_lan"
check_unique "AgentNode" "uq_agentnode_lead_lan_agent"

echo
if [[ "${fail}" -eq 0 ]]; then
  echo "Schema check PASSED."
  exit 0
fi

echo "Schema check FAILED."
exit 1
