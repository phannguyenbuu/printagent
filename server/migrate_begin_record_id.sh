#!/usr/bin/env bash
set -euo pipefail

DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-postgres}"
DB_PASS="${DB_PASS:-myPass}"
DB_NAME="${DB_NAME:-GoPrinx}"

export PGPASSWORD="${DB_PASS}"

psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" <<'SQL'
ALTER TABLE "CounterInfor" ADD COLUMN IF NOT EXISTS begin_record_id INTEGER;
ALTER TABLE "StatusInfor" ADD COLUMN IF NOT EXISTS begin_record_id INTEGER;

CREATE INDEX IF NOT EXISTS idx_counter_begin_record_id ON "CounterInfor"(begin_record_id);
CREATE INDEX IF NOT EXISTS idx_status_begin_record_id ON "StatusInfor"(begin_record_id);

WITH first_counter AS (
  SELECT lead, lan_uid, ip, MIN(id) AS first_id
  FROM "CounterInfor"
  GROUP BY lead, lan_uid, ip
)
UPDATE "CounterInfor" c
SET begin_record_id = f.first_id
FROM first_counter f
WHERE c.lead = f.lead
  AND c.lan_uid = f.lan_uid
  AND c.ip = f.ip
  AND c.begin_record_id IS NULL;

WITH first_status AS (
  SELECT lead, lan_uid, ip, MIN(id) AS first_id
  FROM "StatusInfor"
  GROUP BY lead, lan_uid, ip
)
UPDATE "StatusInfor" s
SET begin_record_id = f.first_id
FROM first_status f
WHERE s.lead = f.lead
  AND s.lan_uid = f.lan_uid
  AND s.ip = f.ip
  AND s.begin_record_id IS NULL;
SQL

echo "Done migrate begin_record_id"
