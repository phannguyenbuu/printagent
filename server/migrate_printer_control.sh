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
  auth_user VARCHAR(128) NOT NULL DEFAULT '',
  auth_password VARCHAR(255) NOT NULL DEFAULT '',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  enabled_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  is_online BOOLEAN NOT NULL DEFAULT TRUE,
  online_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
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

CREATE TABLE IF NOT EXISTS "PrinterOnlineLog" (
  id SERIAL PRIMARY KEY,
  printer_id INTEGER NOT NULL,
  lead VARCHAR(64) NOT NULL,
  lan_uid VARCHAR(128) NOT NULL,
  printer_name VARCHAR(255) NOT NULL DEFAULT '',
  ip VARCHAR(64) NOT NULL DEFAULT '',
  is_online BOOLEAN NOT NULL DEFAULT TRUE,
  changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS "PrinterControlCommand" (
  id SERIAL PRIMARY KEY,
  printer_id INTEGER NOT NULL,
  lead VARCHAR(64) NOT NULL,
  lan_uid VARCHAR(128) NOT NULL,
  agent_uid VARCHAR(128) NOT NULL DEFAULT 'legacy-agent',
  printer_name VARCHAR(255) NOT NULL DEFAULT '',
  ip VARCHAR(64) NOT NULL DEFAULT '',
  desired_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  auth_user VARCHAR(128) NOT NULL DEFAULT '',
  auth_password VARCHAR(255) NOT NULL DEFAULT '',
  status VARCHAR(32) NOT NULL DEFAULT 'pending',
  error_message TEXT NOT NULL DEFAULT '',
  requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  responded_at TIMESTAMPTZ NULL
);

ALTER TABLE "Printer" ADD COLUMN IF NOT EXISTS is_online BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE "Printer" ADD COLUMN IF NOT EXISTS online_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE "Printer" ADD COLUMN IF NOT EXISTS auth_user VARCHAR(128) NOT NULL DEFAULT '';
ALTER TABLE "Printer" ADD COLUMN IF NOT EXISTS auth_password VARCHAR(255) NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_printer_lead ON "Printer"(lead);
CREATE INDEX IF NOT EXISTS idx_printer_lan_uid ON "Printer"(lan_uid);
CREATE INDEX IF NOT EXISTS idx_printer_agent_uid ON "Printer"(agent_uid);
CREATE INDEX IF NOT EXISTS idx_printer_ip ON "Printer"(ip);
CREATE INDEX IF NOT EXISTS idx_printer_enabled ON "Printer"(enabled);
CREATE INDEX IF NOT EXISTS idx_printer_enabled_changed_at ON "Printer"(enabled_changed_at);
CREATE INDEX IF NOT EXISTS idx_printer_is_online ON "Printer"(is_online);
CREATE INDEX IF NOT EXISTS idx_printer_online_changed_at ON "Printer"(online_changed_at);

CREATE INDEX IF NOT EXISTS idx_printer_enable_log_printer_id ON "PrinterEnableLog"(printer_id);
CREATE INDEX IF NOT EXISTS idx_printer_enable_log_lead ON "PrinterEnableLog"(lead);
CREATE INDEX IF NOT EXISTS idx_printer_enable_log_lan_uid ON "PrinterEnableLog"(lan_uid);
CREATE INDEX IF NOT EXISTS idx_printer_enable_log_ip ON "PrinterEnableLog"(ip);
CREATE INDEX IF NOT EXISTS idx_printer_enable_log_enabled ON "PrinterEnableLog"(enabled);
CREATE INDEX IF NOT EXISTS idx_printer_enable_log_changed_at ON "PrinterEnableLog"(changed_at);

CREATE INDEX IF NOT EXISTS idx_printer_online_log_printer_id ON "PrinterOnlineLog"(printer_id);
CREATE INDEX IF NOT EXISTS idx_printer_online_log_lead ON "PrinterOnlineLog"(lead);
CREATE INDEX IF NOT EXISTS idx_printer_online_log_lan_uid ON "PrinterOnlineLog"(lan_uid);
CREATE INDEX IF NOT EXISTS idx_printer_online_log_ip ON "PrinterOnlineLog"(ip);
CREATE INDEX IF NOT EXISTS idx_printer_online_log_is_online ON "PrinterOnlineLog"(is_online);
CREATE INDEX IF NOT EXISTS idx_printer_online_log_changed_at ON "PrinterOnlineLog"(changed_at);

CREATE INDEX IF NOT EXISTS idx_printer_control_cmd_printer_id ON "PrinterControlCommand"(printer_id);
CREATE INDEX IF NOT EXISTS idx_printer_control_cmd_lead ON "PrinterControlCommand"(lead);
CREATE INDEX IF NOT EXISTS idx_printer_control_cmd_lan_uid ON "PrinterControlCommand"(lan_uid);
CREATE INDEX IF NOT EXISTS idx_printer_control_cmd_agent_uid ON "PrinterControlCommand"(agent_uid);
CREATE INDEX IF NOT EXISTS idx_printer_control_cmd_ip ON "PrinterControlCommand"(ip);
CREATE INDEX IF NOT EXISTS idx_printer_control_cmd_desired_enabled ON "PrinterControlCommand"(desired_enabled);
CREATE INDEX IF NOT EXISTS idx_printer_control_cmd_status ON "PrinterControlCommand"(status);
CREATE INDEX IF NOT EXISTS idx_printer_control_cmd_requested_at ON "PrinterControlCommand"(requested_at);
CREATE INDEX IF NOT EXISTS idx_printer_control_cmd_responded_at ON "PrinterControlCommand"(responded_at);
SQL

echo "Done migrate printer control tables"
