#!/usr/bin/env bash
set -euo pipefail

DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-postgres}"
DB_PASS="${DB_PASS:-myPass}"
DB_NAME="${DB_NAME:-GoPrinx}"

export PGPASSWORD="${DB_PASS}"

psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" <<'SQL'
ALTER TABLE "CounterInfor" ADD COLUMN IF NOT EXISTS is_favorite BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE "StatusInfor" ADD COLUMN IF NOT EXISTS is_favorite BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_counter_is_favorite ON "CounterInfor"(is_favorite);
CREATE INDEX IF NOT EXISTS idx_status_is_favorite ON "StatusInfor"(is_favorite);
SQL

echo "Done migrate favorite flag"
