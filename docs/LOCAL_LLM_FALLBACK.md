# Local LLM Fallback With LM Studio

This setup gives you a clean local fallback for coding work without patching or hiding changes inside a third-party tool.

It uses LM Studio's documented local server and OpenAI-compatible API:

- LM Studio API quickstart: https://lmstudio.ai/docs/developer/rest/quickstart
- LM Studio Codex integration: https://lmstudio.ai/docs/integrations/codex
- LM Link option for a separate model machine: https://lmstudio.ai/docs/integrations/lmlink

## What is included in this repo

- `scripts/tools/lmstudio_bridge.py`
  - Minimal Python bridge to LM Studio's local OpenAI-compatible endpoint.
  - Good for file-based prompting or simple automation.
- `scripts/tools/codex_lmstudio.ps1`
  - PowerShell launcher for Codex.
  - `local` mode starts Codex directly against LM Studio.
  - `auto` mode tries normal Codex first, then retries with LM Studio if that run exits with an error.

## 1. Start LM Studio

Install LM Studio, download a model that fits your hardware, load it, then start the local server.

Default API address:

```text
http://localhost:1234
```

LM Studio also ships the `lms` CLI. The documented server start command is:

```powershell
lms server start --port 1234
```

If you enabled authentication in LM Studio, set:

```powershell
$env:LM_STUDIO_API_KEY = "your-token"
```

## 2. Check which model id is available

```powershell
python scripts/tools/lmstudio_bridge.py --list-models
```

Take the exact model id from the output and set it once for convenience:

```powershell
$env:LM_STUDIO_MODEL = "your-model-id"
```

## 3. Use the Python bridge directly

Simple prompt:

```powershell
python scripts/tools/lmstudio_bridge.py "Explain this function"
```

Prompt with attached files:

```powershell
python scripts/tools/lmstudio_bridge.py `
  --system "You are a careful senior software engineer." `
  --file backend/app.py `
  --file agent/services/polling_bridge.py `
  "Review the scan-folder flow and list real risks only."
```

Prompt from a file:

```powershell
python scripts/tools/lmstudio_bridge.py --prompt-file .\tmp\prompt.txt
```

## 4. Run Codex against LM Studio

LM Studio documents a direct Codex integration:

```powershell
codex --oss
```

Or with an explicit local model:

```powershell
codex --oss -m $env:LM_STUDIO_MODEL
```

This repo adds a small wrapper so you do not need to remember the flags.

Run local immediately:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/tools/codex_lmstudio.ps1 -Mode local
```

Run cloud first, then fallback to LM Studio if that run exits with an error:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/tools/codex_lmstudio.ps1 -Mode auto
```

You can also pass normal Codex arguments after the script parameters.

## 5. Notes on the fallback behavior

- `auto` mode is a launcher, not a hidden patch.
- It cannot swap providers in the middle of an already-running interactive Codex session.
- It can retry by starting a new local Codex run after the cloud run exits with an error.
- If you want fully local work from the start, use `-Mode local`.

## 6. Suggested usage pattern

- Normal work: `codex`
- Local private/offline work: `scripts/tools/codex_lmstudio.ps1 -Mode local`
- When cloud quota is unreliable: `scripts/tools/codex_lmstudio.ps1 -Mode auto`
- Quick file review without starting Codex: `python scripts/tools/lmstudio_bridge.py ...`

## 7. Hardware reality

A 3060 can still be useful, but pick a model size that actually fits your VRAM and context budget. The LM Studio docs recommend a model and server setup with roughly more than 25k context for coding tools when possible.
