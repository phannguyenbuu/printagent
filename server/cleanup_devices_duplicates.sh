#!/usr/bin/env bash
set -euo pipefail

DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-postgres}"
DB_PASS="${DB_PASS:-myPass}"
DB_NAME="${DB_NAME:-GoPrinx}"

export PGPASSWORD="${DB_PASS}"

psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" <<'SQL'
WITH ranked AS (
  SELECT
    p.id,
    p.lead,
    p.lan_uid,
    p.agent_uid,
    p.printer_name,
    p.ip,
    ROW_NUMBER() OVER (
      PARTITION BY
        p.lead,
        p.lan_uid,
        CASE
          WHEN btrim(COALESCE(p.ip, '')) <> '' THEN 'ip:' || btrim(p.ip)
          ELSE 'name:' || lower(btrim(COALESCE(p.agent_uid, ''))) || ':' || lower(btrim(COALESCE(p.printer_name, '')))
        END
      ORDER BY p.updated_at DESC NULLS LAST, p.id DESC
    ) AS rn,
    FIRST_VALUE(p.id) OVER (
      PARTITION BY
        p.lead,
        p.lan_uid,
        CASE
          WHEN btrim(COALESCE(p.ip, '')) <> '' THEN 'ip:' || btrim(p.ip)
          ELSE 'name:' || lower(btrim(COALESCE(p.agent_uid, ''))) || ':' || lower(btrim(COALESCE(p.printer_name, '')))
        END
      ORDER BY p.updated_at DESC NULLS LAST, p.id DESC
    ) AS keep_id
  FROM "Printer" p
),
to_drop AS (
  SELECT id, keep_id FROM ranked WHERE rn > 1
)
UPDATE "PrinterEnableLog" l
SET printer_id = d.keep_id
FROM to_drop d
WHERE l.printer_id = d.id;

WITH ranked AS (
  SELECT
    p.id,
    ROW_NUMBER() OVER (
      PARTITION BY
        p.lead,
        p.lan_uid,
        CASE
          WHEN btrim(COALESCE(p.ip, '')) <> '' THEN 'ip:' || btrim(p.ip)
          ELSE 'name:' || lower(btrim(COALESCE(p.agent_uid, ''))) || ':' || lower(btrim(COALESCE(p.printer_name, '')))
        END
      ORDER BY p.updated_at DESC NULLS LAST, p.id DESC
    ) AS rn,
    FIRST_VALUE(p.id) OVER (
      PARTITION BY
        p.lead,
        p.lan_uid,
        CASE
          WHEN btrim(COALESCE(p.ip, '')) <> '' THEN 'ip:' || btrim(p.ip)
          ELSE 'name:' || lower(btrim(COALESCE(p.agent_uid, ''))) || ':' || lower(btrim(COALESCE(p.printer_name, '')))
        END
      ORDER BY p.updated_at DESC NULLS LAST, p.id DESC
    ) AS keep_id
  FROM "Printer" p
),
to_drop AS (
  SELECT id, keep_id FROM ranked WHERE rn > 1
)
UPDATE "PrinterOnlineLog" l
SET printer_id = d.keep_id
FROM to_drop d
WHERE l.printer_id = d.id;

WITH ranked AS (
  SELECT
    p.id,
    ROW_NUMBER() OVER (
      PARTITION BY
        p.lead,
        p.lan_uid,
        CASE
          WHEN btrim(COALESCE(p.ip, '')) <> '' THEN 'ip:' || btrim(p.ip)
          ELSE 'name:' || lower(btrim(COALESCE(p.agent_uid, ''))) || ':' || lower(btrim(COALESCE(p.printer_name, '')))
        END
      ORDER BY p.updated_at DESC NULLS LAST, p.id DESC
    ) AS rn
  FROM "Printer" p
)
DELETE FROM "Printer" p
USING ranked r
WHERE p.id = r.id
  AND r.rn > 1;
SQL

echo "Done cleanup duplicate devices"
