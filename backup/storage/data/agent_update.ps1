param(
  [int]$Pid,
  [string]$Target,
  [string]$Staged,
  [string]$Backup,
  [string]$RelaunchArgsBase64
)
$ErrorActionPreference = 'Stop'
$HelperLog = Join-Path (Split-Path -Parent $PSCommandPath) 'agent_update.log'
function Write-HelperLog([string]$Message) { Add-Content -LiteralPath $HelperLog -Value ((Get-Date).ToString('o') + ' ' + $Message) }
Write-HelperLog "starting pid=$Pid target=$Target staged=$Staged"
while (Get-Process -Id $Pid -ErrorAction SilentlyContinue) {
  Start-Sleep -Seconds 1
}
Write-HelperLog 'original process exited'
Start-Sleep -Seconds 5
if (Test-Path -LiteralPath $Backup) { Remove-Item -LiteralPath $Backup -Force }
if (Test-Path -LiteralPath $Target) { Move-Item -LiteralPath $Target -Destination $Backup -Force }
Move-Item -LiteralPath $Staged -Destination $Target -Force
Write-HelperLog 'staged binary moved into place'
$relaunchArgs = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($RelaunchArgsBase64)) | ConvertFrom-Json
if ($null -eq $relaunchArgs) { $relaunchArgs = @() }
if ($relaunchArgs -isnot [System.Array]) { $relaunchArgs = @($relaunchArgs) }
$workingDir = Split-Path -Parent $Target
Write-HelperLog ('relaunch args=' + ($relaunchArgs -join ' '))
Start-Process -WindowStyle Hidden -WorkingDirectory $workingDir -FilePath $Target -ArgumentList $relaunchArgs
Write-HelperLog 'relaunch started'
Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue
