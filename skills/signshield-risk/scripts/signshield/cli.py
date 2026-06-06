from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .analyzer import analyze_transaction
from .compact import compact_report
from .llm_summary import apply_llm_summary
from .token_metadata import TokenMetadataResolver
from .types import DEFAULT_REQUEST_TIMEOUT, AnalysisOptions


def iter_input_files(path: Path) -> list[Path]:
    if path.is_dir():
        return sorted(p for p in path.iterdir() if p.suffix.lower() == ".json")
    return [path]


def write_result(result: dict, output_dir: Path | None, source: Path) -> None:
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if output_dir is None:
        print(text)
        return
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / f"{source.stem}.risk.json"
    target.write_text(text + "\n", encoding="utf-8")
    print(str(target))


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze EVM transaction JSON and produce SignShield risk JSON.")
    parser.add_argument("input", type=Path, help="Input JSON file or directory containing JSON files.")
    parser.add_argument("--output", type=Path, help="Directory for .risk.json outputs. Defaults to stdout.")
    parser.add_argument("--live", action="store_true", help="Enable live external adapters where configured.")
    parser.add_argument("--mode", choices=["offline", "live-best-effort", "production"], help="Runtime mode. --live maps to live-best-effort when omitted.")
    parser.add_argument("--tenderly-account", default=os.getenv("TENDERLY_ACCOUNT_SLUG"))
    parser.add_argument("--tenderly-project", default=os.getenv("TENDERLY_PROJECT_SLUG"))
    parser.add_argument("--tenderly-access-key", default=os.getenv("TENDERLY_ACCESS_KEY"))
    parser.add_argument("--etherscan-api-key", default=os.getenv("ETHERSCAN_API_KEY"))
    parser.add_argument("--blockscout-base-url", default=os.getenv("BLOCKSCOUT_BASE_URL"))
    parser.add_argument("--rpc-url", default=os.getenv("SIGNSSHIELD_RPC_URL"))
    parser.add_argument("--no-public-rpc-fallback", action="store_true", help="Disable public RPC fallback when --live is enabled and --rpc-url is absent.")
    parser.add_argument("--goplus-base-url", default=os.getenv("GOPLUS_BASE_URL", "https://api.gopluslabs.io"))
    parser.add_argument("--metamask-config-url", default=os.getenv("METAMASK_CONFIG_URL", "https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json"))
    parser.add_argument("--timeout", type=float, default=float(os.getenv("SIGNSSHIELD_TIMEOUT", DEFAULT_REQUEST_TIMEOUT)), help="HTTP request timeout for live providers in seconds.")
    parser.add_argument("--subagent", choices=["off", "dry-run", "live"], default=os.getenv("SIGNSSHIELD_SUBAGENT_MODE", "off"))
    parser.add_argument("--subagent-command", default=os.getenv("SIGNSSHIELD_SUBAGENT_COMMAND"))
    parser.add_argument("--agent-loop", choices=["off", "kimi"], default=os.getenv("SIGNSSHIELD_AGENT_LOOP", "off"), help="Use an agent loop for the final risk report. Defaults to off.")
    parser.add_argument(
        "--agent-loop-model",
        default=os.getenv("SIGNSSHIELD_AGENT_LOOP_MODEL") or os.getenv("KIMI_AGENT_MODEL"),
        help="Kimi Agent SDK model key for the agent loop. Defaults to kimi-code/kimi-for-coding.",
    )
    parser.add_argument("--agent-loop-timeout", type=float, default=float(os.getenv("SIGNSSHIELD_AGENT_LOOP_TIMEOUT", DEFAULT_REQUEST_TIMEOUT)), help="Agent loop timeout in seconds.")
    parser.add_argument("--agent-loop-max-steps", type=int, default=int(os.getenv("SIGNSSHIELD_AGENT_LOOP_MAX_STEPS", "6")), help="Maximum Kimi agent steps for one analysis turn.")
    parser.add_argument("--no-agent-loop-fallback", action="store_true", help="Raise agent-loop failures instead of falling back to deterministic analysis.")
    parser.add_argument("--output-format", choices=["compact", "full"], default="compact", help="Output compact user JSON by default; use full for forensic evidence.")
    parser.add_argument("--summary-llm", choices=["off", "live"], default="live", help="Apply final LLM summary to compact output. Full output never calls this layer.")
    parser.add_argument("--allow-fixture-risk", action="store_true", help="Allow local fixture labels to create high-confidence risk factors outside offline mode.")
    args = parser.parse_args()
    mode = args.mode or ("live-best-effort" if args.live else "offline")

    options = AnalysisOptions(
        live=args.live,
        mode=mode,
        timeout=args.timeout,
        tenderly_account=args.tenderly_account,
        tenderly_project=args.tenderly_project,
        tenderly_access_key=args.tenderly_access_key,
        etherscan_api_key=args.etherscan_api_key,
        blockscout_base_url=args.blockscout_base_url,
        rpc_url=args.rpc_url,
        public_rpc_fallback=not args.no_public_rpc_fallback,
        goplus_base_url=args.goplus_base_url,
        metamask_config_url=args.metamask_config_url,
        subagent_mode=args.subagent,
        subagent_command=args.subagent_command,
        allow_fixture_risk=(mode == "offline" or args.allow_fixture_risk),
        agent_loop=args.agent_loop,
        agent_loop_backend="kimi",
        agent_loop_model=args.agent_loop_model,
        agent_loop_timeout=args.agent_loop_timeout,
        agent_loop_max_steps=args.agent_loop_max_steps,
        agent_loop_fallback=not args.no_agent_loop_fallback,
    )

    files = iter_input_files(args.input)
    if not files:
        raise SystemExit(f"No JSON inputs found: {args.input}")
    token_metadata_provider = TokenMetadataResolver(args.rpc_url, public_fallback=mode != "offline" and not args.no_public_rpc_fallback)
    for source in files:
        payload = json.loads(source.read_text(encoding="utf-8"))
        result = analyze_transaction(payload, str(source), options=options, token_metadata_provider=token_metadata_provider)
        if args.output_format == "compact":
            result = compact_report(result)
            result = apply_llm_summary(result, mode=args.summary_llm)
        write_result(result, args.output, source)
    return 0
