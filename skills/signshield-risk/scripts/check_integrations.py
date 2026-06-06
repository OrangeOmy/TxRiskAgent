#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from signshield.adapters.contract_reputation import CompositeContractReputationAdapter  # noqa: E402
from signshield.adapters.simulation import TenderlySimulationAdapter  # noqa: E402
from signshield.adapters.threat_intel import CompositeThreatIntelAdapter  # noqa: E402
from signshield.rpc import check_public_rpc_endpoints  # noqa: E402


def main() -> int:
    etherscan_key = os.getenv("ETHERSCAN_API_KEY")
    contract_adapter = CompositeContractReputationAdapter(etherscan_key, os.getenv("BLOCKSCOUT_BASE_URL"))
    simulation_adapter = TenderlySimulationAdapter(
        os.getenv("TENDERLY_ACCOUNT_SLUG"),
        os.getenv("TENDERLY_PROJECT_SLUG"),
        os.getenv("TENDERLY_ACCESS_KEY"),
    )
    threat_adapter = CompositeThreatIntelAdapter()
    checks = {
        "publicRpc": check_public_rpc_endpoints(),
        "tenderly": simulation_adapter.simulate(
            1,
            {
                "from": "0x0000000000000000000000000000000000000001",
                "to": "0x0000000000000000000000000000000000000002",
                "value": "0x0",
                "data": "0x",
            },
        ),
        "etherscan": contract_adapter.inspect(1, "0xdac17f958d2ee523a2206206994597c13d831ec7").get("etherscan", {}),
        "goplusMetamask": threat_adapter.inspect(1, ["0xdac17f958d2ee523a2206206994597c13d831ec7"], "https://app.uniswap.org"),
    }
    print(json.dumps(redact(checks), ensure_ascii=False, indent=2))
    return 0


def redact(value):
    if isinstance(value, dict):
        return {key: redact(item) for key, item in value.items() if key not in {"SourceCode", "apikey"}}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


if __name__ == "__main__":
    raise SystemExit(main())
