from __future__ import annotations

import logging
import subprocess
from typing import Any


LOGGER = logging.getLogger(__name__)


def ensure_ftp_firewall_rules(control_port: int) -> dict[str, Any]:
    rules = [
        {
            "name": f"PrintAgent FTP Control {control_port}",
            "port": str(control_port),
        },
        {
            "name": "PrintAgent FTP Passive 30000-30049",
            "port": "30000-30049",
        },
    ]
    applied: list[dict[str, str]] = []
    errors: list[str] = []
    for rule in rules:
        name = rule["name"]
        port = rule["port"]
        try:
            show_cmd = ["netsh", "advfirewall", "firewall", "show", "rule", f'name={name}']
            LOGGER.info("Firewall check start: name=%s port=%s", name, port)
            show_result = subprocess.run(show_cmd, capture_output=True, text=True, timeout=10)
            exists = show_result.returncode == 0 and "Rule Name:" in (show_result.stdout or "")
            LOGGER.info(
                "Firewall check done: name=%s exists=%s returncode=%s",
                name,
                exists,
                show_result.returncode,
            )
            if exists:
                set_cmd = [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "set",
                    "rule",
                    f'name={name}',
                    "new",
                    "enable=Yes",
                ]
                set_result = subprocess.run(set_cmd, capture_output=True, text=True, timeout=10)
                if set_result.returncode == 0:
                    applied.append({"name": name, "port": port, "action": "enabled"})
                    LOGGER.info("Firewall rule enabled: name=%s", name)
                else:
                    error_text = (set_result.stderr or set_result.stdout or "").strip() or f"cannot enable {name}"
                    errors.append(error_text)
                    LOGGER.warning("Firewall enable failed: name=%s error=%s", name, error_text)
            else:
                add_cmd = [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    f'name={name}',
                    "dir=in",
                    "action=allow",
                    "protocol=TCP",
                    f"localport={port}",
                ]
                add_result = subprocess.run(add_cmd, capture_output=True, text=True, timeout=10)
                if add_result.returncode == 0:
                    applied.append({"name": name, "port": port, "action": "added"})
                    LOGGER.info("Firewall rule added: name=%s port=%s", name, port)
                else:
                    error_text = (add_result.stderr or add_result.stdout or "").strip() or f"cannot add {name}"
                    errors.append(error_text)
                    LOGGER.warning("Firewall add failed: name=%s error=%s", name, error_text)
        except Exception as exc:  # noqa: BLE001
            err = str(exc)
            errors.append(err)
            LOGGER.exception("Firewall operation exception: name=%s error=%s", name, err)
    summary = {"ok": len(errors) == 0, "rules": applied, "errors": errors}
    LOGGER.info("Firewall ensure summary: control_port=%s ok=%s applied=%s errors=%s", control_port, summary["ok"], len(applied), len(errors))
    return summary

