from __future__ import annotations

import argparse
import logging
import signal
import sys
import time

import yaml

from relay import Relay


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    if not config or "servers" not in config:
        raise ValueError(f"config {path!r} has no 'servers' section")
    return config


def main() -> None:
    parser = argparse.ArgumentParser(description="CoT Relay — multi-TAK-server CoT bridge")
    parser.add_argument("--config", default="config.yaml", help="путь к YAML-конфигу (по умолчанию config.yaml)")
    parser.add_argument("--verbose", action="store_true", help="включить debug-логирование")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    try:
        config = load_config(args.config)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        logging.getLogger("relay.main").error("failed to load config: %s", exc)
        sys.exit(1)

    relay = Relay(config)
    relay.start()

    stop_flag = {"stop": False}

    def _handle_signal(signum, frame):  # noqa: ANN001, ARG001
        stop_flag["stop"] = True

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    try:
        while not stop_flag["stop"]:
            time.sleep(1)
    finally:
        relay.stop()


if __name__ == "__main__":
    main()
