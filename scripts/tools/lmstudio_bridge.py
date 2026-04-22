#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_BASE_URL = "http://localhost:1234"
DEFAULT_TIMEOUT = 120


def _normalize_base_url(base_url: str) -> str:
    text = (base_url or DEFAULT_BASE_URL).strip().rstrip("/")
    if text.endswith("/v1"):
        return text
    return f"{text}/v1"


def _headers(api_key: str) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    token = api_key.strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _request_json(
    method: str,
    url: str,
    *,
    payload: dict[str, Any] | None = None,
    headers: dict[str, str],
    timeout: int,
) -> dict[str, Any]:
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"HTTP {exc.code} from LM Studio: {detail}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"Could not reach LM Studio at {url}: {exc.reason}") from exc
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"LM Studio returned invalid JSON: {body[:400]}") from exc


def list_models(*, base_url: str, api_key: str, timeout: int) -> list[dict[str, Any]]:
    payload = _request_json(
        "GET",
        f"{base_url}/models",
        headers=_headers(api_key),
        timeout=timeout,
    )
    data = payload.get("data")
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def resolve_model(args: argparse.Namespace) -> str:
    if args.model:
        return args.model
    models = list_models(base_url=args.base_url, api_key=args.api_key, timeout=args.timeout)
    if not models:
        raise SystemExit("No local model found in LM Studio. Load a model first.")
    model_id = str(models[0].get("id") or "").strip()
    if not model_id:
        raise SystemExit("LM Studio returned a model list but the first entry had no id.")
    return model_id


def build_user_content(args: argparse.Namespace) -> str:
    chunks: list[str] = []
    prompt = (args.prompt or "").strip()
    if args.prompt_file:
        prompt = Path(args.prompt_file).read_text(encoding="utf-8").strip()
    if prompt:
        chunks.append(prompt)
    for file_path in args.file or []:
        path = Path(file_path)
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = path.read_text(encoding="utf-8", errors="replace")
        chunks.append(f"File: {path}\n```text\n{text}\n```")
    return "\n\n".join(chunk for chunk in chunks if chunk.strip())


def chat(args: argparse.Namespace) -> str:
    model = resolve_model(args)
    content = build_user_content(args)
    if not content:
        raise SystemExit("Missing prompt. Pass text directly or use --prompt-file.")

    messages: list[dict[str, str]] = []
    system_prompt = (args.system or "").strip()
    if args.system_file:
        system_prompt = Path(args.system_file).read_text(encoding="utf-8").strip()
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": content})

    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
    }
    if args.temperature is not None:
        payload["temperature"] = args.temperature
    if args.max_tokens is not None:
        payload["max_tokens"] = args.max_tokens

    response = _request_json(
        "POST",
        f"{args.base_url}/chat/completions",
        payload=payload,
        headers=_headers(args.api_key),
        timeout=args.timeout,
    )

    choices = response.get("choices")
    if not isinstance(choices, list) or not choices:
        raise SystemExit(f"LM Studio returned no choices: {json.dumps(response)[:800]}")
    message = choices[0].get("message") if isinstance(choices[0], dict) else None
    if not isinstance(message, dict):
        raise SystemExit(f"LM Studio returned an unexpected choice payload: {json.dumps(response)[:800]}")
    content_value = message.get("content")
    if isinstance(content_value, str):
        return content_value
    if isinstance(content_value, list):
        rendered: list[str] = []
        for item in content_value:
            if isinstance(item, dict) and item.get("type") == "text":
                rendered.append(str(item.get("text") or ""))
        if rendered:
            return "\n".join(rendered)
    raise SystemExit(f"LM Studio returned an unsupported content format: {json.dumps(response)[:800]}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Small bridge script for talking to LM Studio's OpenAI-compatible local API.",
    )
    parser.add_argument("prompt", nargs="?", help="Prompt text to send to the local model.")
    parser.add_argument(
        "--base-url",
        default=os.environ.get("LM_STUDIO_BASE_URL", DEFAULT_BASE_URL),
        help="LM Studio base URL. Accepts either http://host:port or http://host:port/v1",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("LM_STUDIO_API_KEY", ""),
        help="Optional LM Studio API token when authentication is enabled.",
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("LM_STUDIO_MODEL", ""),
        help="Model id to use. If omitted, the first loaded local model is used.",
    )
    parser.add_argument("--system", default="", help="Optional system prompt.")
    parser.add_argument("--system-file", default="", help="Read the system prompt from a file.")
    parser.add_argument("--prompt-file", default="", help="Read the user prompt from a file.")
    parser.add_argument(
        "--file",
        action="append",
        default=[],
        help="Attach a file's text content to the prompt. May be repeated.",
    )
    parser.add_argument("--temperature", type=float, default=0.2, help="Sampling temperature.")
    parser.add_argument("--max-tokens", type=int, default=2048, help="Max output tokens.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout in seconds.")
    parser.add_argument("--list-models", action="store_true", help="List loaded LM Studio models and exit.")
    parser.add_argument("--raw", action="store_true", help="Print the raw model list when using --list-models.")
    args = parser.parse_args()
    args.base_url = _normalize_base_url(args.base_url)
    return args


def main() -> int:
    args = parse_args()
    if args.list_models:
        models = list_models(base_url=args.base_url, api_key=args.api_key, timeout=args.timeout)
        if args.raw:
            print(json.dumps(models, ensure_ascii=False, indent=2))
            return 0
        for item in models:
            model_id = str(item.get("id") or "").strip()
            if model_id:
                print(model_id)
        return 0
    print(chat(args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
