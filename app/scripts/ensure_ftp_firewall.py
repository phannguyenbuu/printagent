from __future__ import annotations

import argparse
import json
import logging

from app.utils.firewall import ensure_ftp_firewall_rules


def main() -> int:
    parser = argparse.ArgumentParser(description="Ensure FTP firewall rules for PrintAgent")
    parser.add_argument("--control-port", type=int, default=2121, help="FTP control port")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    result = ensure_ftp_firewall_rules(args.control_port)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if bool(result.get("ok")) else 1


if __name__ == "__main__":
    raise SystemExit(main())

