param(
    [switch]$Clean,
    [switch]$RecreateVenv
)

$ErrorActionPreference = "Stop"
# Script lives in scripts/tools/ — resolve project root (2 levels up)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent (Split-Path -Parent $scriptDir)
Set-Location $root

if ($Clean) {
    Remove-Item -Recurse -Force "build","dist" -ErrorAction SilentlyContinue
}

$venvPath = Join-Path $root ".build-venv"
if ($RecreateVenv -and (Test-Path $venvPath)) {
    Remove-Item -Recurse -Force $venvPath
}
if (-not (Test-Path $venvPath)) {
    python -m venv $venvPath
}
$venvPython = Join-Path $venvPath "Scripts\python.exe"

Write-Host "Stopping running printagent.exe instances..." -ForegroundColor Yellow
Get-Process printagent -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

if (Test-Path "dist\printagent.exe") {
    Remove-Item -Force "dist\printagent.exe" -ErrorAction SilentlyContinue
}
if (Test-Path "dist\config.yaml") {
    Remove-Item -Force "dist\config.yaml" -ErrorAction SilentlyContinue
}

Write-Host "Installing dependencies..." -ForegroundColor Cyan
& $venvPython -m pip install --upgrade pip | Out-Null
& $venvPython -m pip install -r requirements.txt pyinstaller | Out-Null
& $venvPython -m pip uninstall -y pillow pystray pyyaml python-dotenv | Out-Null

$iconArg = @()
if (Test-Path "agent\icon.ico") {
    $iconArg = @("--icon", "agent\icon.ico")
}

$pyInstallerArgs = @(
    "--noconfirm",
    "--clean",
    "--onefile",
    "--noconsole",
    "--name", "printagent",
    "--paths", ".",
    "--collect-submodules", "agent.modules",
    "--collect-submodules", "agent.services",
    "--collect-submodules", "agent.utils",
    "--hidden-import", "agent.services.tray",
    "--exclude-module", "torch",
    "--exclude-module", "torchvision",
    "--exclude-module", "torchaudio",
    "--exclude-module", "sklearn",
    "--exclude-module", "scipy",
    "--exclude-module", "matplotlib",
    "--exclude-module", "numba",
    "--exclude-module", "llvmlite",
    "--exclude-module", "pandas",
    "--exclude-module", "cv2",
    "--exclude-module", "PIL",
    "--exclude-module", "imageio_ffmpeg",
    "--exclude-module", "IPython",
    "--exclude-module", "jupyter",
    "--exclude-module", "notebook",
    "--exclude-module", "traitlets",
    "--add-data", "agent/templates;agent/templates"
) + $iconArg + @("agent/main.py")

Write-Host "Running PyInstaller..." -ForegroundColor Cyan
& $venvPython -m PyInstaller @pyInstallerArgs

Write-Host ""
Write-Host "Build completed: $root\dist\printagent.exe" -ForegroundColor Green

if (Test-Path "dist\printagent.exe") {
    Write-Host "Restarting printagent.exe in background..." -ForegroundColor Yellow
    Start-Process -FilePath "dist\printagent.exe" -WorkingDirectory "dist" -WindowStyle Hidden
    Write-Host "Agent restarted successfully OK" -ForegroundColor Green
}
