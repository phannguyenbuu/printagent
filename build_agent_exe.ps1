param(
    [switch]$Clean,
    [switch]$RecreateVenv
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

if ($Clean) {
    Remove-Item -Recurse -Force "build","dist","printagent.spec" -ErrorAction SilentlyContinue
}

$venvPath = Join-Path $root ".build-venv"
if ($RecreateVenv -and (Test-Path $venvPath)) {
    Remove-Item -Recurse -Force $venvPath
}
if (-not (Test-Path $venvPath)) {
    python -m venv $venvPath
}
$venvPython = Join-Path $venvPath "Scripts\\python.exe"

& $venvPython -m pip install --upgrade pip | Out-Null
& $venvPython -m pip install -r requirements.txt pyinstaller appdirs | Out-Null

& $venvPython -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --name "printagent" `
    --collect-data openpyxl `
    --collect-submodules openpyxl `
    --collect-submodules app.modules `
    --collect-submodules app.services `
    --hidden-import "appdirs" `
    --exclude-module torch `
    --exclude-module torchvision `
    --exclude-module torchaudio `
    --exclude-module sklearn `
    --exclude-module scipy `
    --exclude-module matplotlib `
    --exclude-module numba `
    --exclude-module llvmlite `
    --exclude-module pandas `
    --exclude-module cv2 `
    --exclude-module imageio_ffmpeg `
    --exclude-module IPython `
    --exclude-module jupyter `
    --exclude-module notebook `
    --exclude-module traitlets `
    --add-data "app/templates;app/templates" `
    --add-data "config.yaml;." `
    "app/main.py"

Write-Host "Build completed: $root\dist\printagent.exe"
