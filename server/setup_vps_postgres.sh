#!/usr/bin/env bash
set -euo pipefail

# GoPrinx PostgreSQL bootstrap (Linux VPS)
# Assumptions:
# - You are already inside project venv with dependencies installed.
# - PostgreSQL password for user postgres is myPass.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}"
DB_NAME="GoPrinx"
DB_USER="postgres"
DB_PASS="myPass"

cd "${PROJECT_ROOT}"

echo "[1/4] Checking PostgreSQL tools..."
command -v psql >/dev/null 2>&1 || { echo "ERROR: psql not found in PATH."; exit 1; }

echo "[2/4] Ensuring PostgreSQL service is running..."
systemctl enable postgresql >/dev/null 2>&1 || true
systemctl start postgresql

echo "[3/4] Verifying/setting postgres password..."
su - postgres -c "psql -c \"ALTER USER ${DB_USER} WITH PASSWORD '${DB_PASS}';\"" >/dev/null

echo "[4/4] Creating database ${DB_NAME} + initializing tables..."
DB_EXISTS=$(su - postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='${DB_NAME}';\"" | tr -d '[:space:]')
if [[ "${DB_EXISTS}" != "1" ]]; then
  su - postgres -c "createdb ${DB_NAME}"
fi

if [[ -z "${VIRTUAL_ENV:-}" ]]; then
  echo "ERROR: No active virtualenv. Activate your venv first."
  exit 1
fi
export DATABASE_URL="postgresql+psycopg2://postgres:myPass@localhost:5432/GoPrinx"
python init_db.py

echo
echo "DONE."
echo "Run server:"
echo "  export DATABASE_URL=postgresql+psycopg2://postgres:myPass@localhost:5432/GoPrinx"
echo "  export LEAD_KEYS=default:change-me"
echo "  python app.py"
