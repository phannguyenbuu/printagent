param(
  [ValidateSet("local", "auto")]
  [string]$Mode = "local",
  [string]$Model = "",
  [string]$BaseUrl = "",
  [string]$ApiKey = "",
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$CodexArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-LmStudioApiBase {
  param([string]$RawBaseUrl)
  $value = $RawBaseUrl
  if (-not $value) { $value = $env:LM_STUDIO_BASE_URL }
  if (-not $value) { $value = "http://localhost:1234" }
  $value = $value.TrimEnd("/")
  if ($value.EndsWith("/v1")) { return $value }
  return "$value/v1"
}

function Get-LmStudioHeaders {
  param([string]$Token)
  $headers = @{}
  if ($Token) { $headers["Authorization"] = "Bearer $Token" }
  return $headers
}

function Get-LmStudioModels {
  param(
    [string]$ApiBase,
    [string]$Token
  )
  $uri = "$ApiBase/models"
  $response = Invoke-RestMethod -Method Get -Uri $uri -Headers (Get-LmStudioHeaders -Token $Token) -TimeoutSec 5
  if ($null -eq $response.data) { return @() }
  return @($response.data)
}

function Resolve-LocalModel {
  param(
    [string]$RequestedModel,
    [string]$ApiBase,
    [string]$Token
  )
  if ($RequestedModel) { return $RequestedModel }
  if ($env:LM_STUDIO_MODEL) { return $env:LM_STUDIO_MODEL }
  $models = Get-LmStudioModels -ApiBase $ApiBase -Token $Token
  foreach ($item in $models) {
    $id = "$($item.id)".Trim()
    if ($id) { return $id }
  }
  throw "No loaded model found in LM Studio. Load a model first."
}

function Test-LmStudioOnline {
  param(
    [string]$ApiBase,
    [string]$Token
  )
  try {
    $null = Get-LmStudioModels -ApiBase $ApiBase -Token $Token
    return $true
  } catch {
    return $false
  }
}

function Invoke-CodexLocal {
  param(
    [string]$SelectedModel,
    [string[]]$ExtraArgs
  )
  $args = @("--oss")
  if ($SelectedModel) {
    $args += @("-m", $SelectedModel)
  }
  if ($ExtraArgs) {
    $args += $ExtraArgs
  }
  Write-Host "Launching Codex against LM Studio with model: $SelectedModel"
  & codex @args
  return $LASTEXITCODE
}

if (-not (Get-Command codex -ErrorAction SilentlyContinue)) {
  throw "Could not find 'codex' on PATH."
}

$apiBase = Resolve-LmStudioApiBase -RawBaseUrl $BaseUrl
if (-not $ApiKey) { $ApiKey = $env:LM_STUDIO_API_KEY }

if ($Mode -eq "local") {
  if (-not (Test-LmStudioOnline -ApiBase $apiBase -Token $ApiKey)) {
    throw "LM Studio is not reachable at $apiBase. Start LM Studio server first."
  }
  $selectedModel = Resolve-LocalModel -RequestedModel $Model -ApiBase $apiBase -Token $ApiKey
  exit (Invoke-CodexLocal -SelectedModel $selectedModel -ExtraArgs $CodexArgs)
}

Write-Host "Launching Codex in normal cloud mode."
& codex @CodexArgs
$cloudExitCode = $LASTEXITCODE
if ($cloudExitCode -eq 0) {
  exit 0
}

if (-not (Test-LmStudioOnline -ApiBase $apiBase -Token $ApiKey)) {
  Write-Warning "Cloud run exited with code $cloudExitCode and LM Studio is not reachable at $apiBase."
  exit $cloudExitCode
}

$fallbackModel = Resolve-LocalModel -RequestedModel $Model -ApiBase $apiBase -Token $ApiKey
Write-Warning "Cloud run exited with code $cloudExitCode. Falling back to LM Studio."
exit (Invoke-CodexLocal -SelectedModel $fallbackModel -ExtraArgs $CodexArgs)
