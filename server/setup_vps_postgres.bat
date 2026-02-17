@echo off
setlocal ENABLEDELAYEDEXPANSION

REM -----------------------------
REM GoPrinx PostgreSQL bootstrap
REM -----------------------------
set DB_HOST=localhost
set DB_PORT=5432
set DB_USER=postgres
set DB_PASS=myPass
set DB_NAME=GoPrinx

echo [1/5] Checking psql...
where psql >nul 2>nul
if errorlevel 1 (
  echo ERROR: psql not found in PATH. Install PostgreSQL first and add bin folder to PATH.
  exit /b 1
)

set PGPASSWORD=%DB_PASS%

echo [2/5] Checking PostgreSQL connection...
psql -h %DB_HOST% -p %DB_PORT% -U %DB_USER% -d postgres -c "SELECT version();" >nul
if errorlevel 1 (
  echo ERROR: Cannot connect to PostgreSQL with current credentials.
  exit /b 1
)

echo [3/5] Creating database if not exists...
psql -h %DB_HOST% -p %DB_PORT% -U %DB_USER% -d postgres -tc "SELECT 1 FROM pg_database WHERE datname='%DB_NAME%';" | findstr /C:"1" >nul
if errorlevel 1 (
  createdb -h %DB_HOST% -p %DB_PORT% -U %DB_USER% %DB_NAME%
  if errorlevel 1 (
    echo ERROR: Cannot create database %DB_NAME%.
    exit /b 1
  )
)

echo [4/5] Installing Python dependencies...
python -m pip install -r "%~dp0requirements.txt"
if errorlevel 1 (
  echo ERROR: pip install failed.
  exit /b 1
)

echo [5/5] Initializing tables CounterInfor and StatusInfor...
set DATABASE_URL=postgresql+psycopg2://%DB_USER%:%DB_PASS%@%DB_HOST%:%DB_PORT%/%DB_NAME%
python "%~dp0init_db.py"
if errorlevel 1 (
  echo ERROR: Table initialization failed.
  exit /b 1
)

echo.
echo DONE.
echo Start server with:
echo   set DATABASE_URL=%DATABASE_URL%
echo   set LEAD_KEYS=default:change-me
echo   python "%~dp0app.py"
exit /b 0
