#!/usr/bin/env bash
set -euo pipefail

DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-postgres}"
DB_PASS="${DB_PASS:-myPass}"
DB_NAME="${DB_NAME:-GoPrinx}"

export PGPASSWORD="${DB_PASS}"

psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" <<'SQL'
CREATE TABLE IF NOT EXISTS "Printer" (
  id SERIAL PRIMARY KEY,
  lead VARCHAR(64) NOT NULL,
  lan_uid VARCHAR(128) NOT NULL,
  agent_uid VARCHAR(128) NOT NULL DEFAULT 'legacy-agent',
  printer_name VARCHAR(255) NOT NULL DEFAULT '',
  ip VARCHAR(64) NOT NULL DEFAULT '',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  enabled_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS "PrinterEnableLog" (
  id SERIAL PRIMARY KEY,
  printer_id INTEGER NOT NULL,
  lead VARCHAR(64) NOT NULL,
  lan_uid VARCHAR(128) NOT NULL,
  printer_name VARCHAR(255) NOT NULL DEFAULT '',
  ip VARCHAR(64) NOT NULL DEFAULT '',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_printer_lead ON "Printer"(lead);
CREATE INDEX IF NOT EXISTS idx_printer_lan_uid ON "Printer"(lan_uid);
CREATE INDEX IF NOT EXISTS idx_printer_agent_uid ON "Printer"(agent_uid);
CREATE INDEX IF NOT EXISTS idx_printer_ip ON "Printer"(ip);
CREATE INDEX IF NOT EXISTS idx_printer_enabled ON "Printer"(enabled);
CREATE INDEX IF NOT EXISTS idx_printer_enabled_changed_at ON "Printer"(enabled_changed_at);

CREATE INDEX IF NOT EXISTS idx_printer_enable_log_printer_id ON "PrinterEnableLog"(printer_id);
CREATE INDEX IF NOT EXISTS idx_printer_enable_log_lead ON "PrinterEnableLog"(lead);
CREATE INDEX IF NOT EXISTS idx_printer_enable_log_lan_uid ON "PrinterEnableLog"(lan_uid);
CREATE INDEX IF NOT EXISTS idx_printer_enable_log_ip ON "PrinterEnableLog"(ip);
CREATE INDEX IF NOT EXISTS idx_printer_enable_log_enabled ON "PrinterEnableLog"(enabled);
CREATE INDEX IF NOT EXISTS idx_printer_enable_log_changed_at ON "PrinterEnableLog"(changed_at);
SQL

echo "Done migrate printer control tables"
