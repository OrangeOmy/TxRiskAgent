from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from signshield.http_service import create_app


def main() -> None:
    parser = argparse.ArgumentParser(description="Export the TxRiskAgent OpenAPI schema as YAML.")
    parser.add_argument("--output", default="openapi.yaml", help="Output YAML path.")
    parser.add_argument(
        "--server-url",
        default="http://localhost:8000",
        help="Public base URL to place in the OpenAPI servers list.",
    )
    args = parser.parse_args()

    schema = create_app().openapi()
    schema["servers"] = [{"url": args.server_url.rstrip("/")}]
    output_path = Path(args.output)
    output_path.write_text(yaml.safe_dump(schema, sort_keys=False, allow_unicode=True), encoding="utf-8")
    print(f"Wrote {output_path}")


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    main()
