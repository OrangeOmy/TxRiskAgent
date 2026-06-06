from __future__ import annotations

import json
from pathlib import Path

from signshield import analyze_transaction
from signshield.types import AnalysisOptions


ROOT = Path(__file__).resolve().parents[1]


def load_dump(name_prefix: str) -> dict:
    path = next((ROOT / "dump-tx").glob(f"{name_prefix}*.json"))
    return json.loads(path.read_text(encoding="utf-8"))


def test_bsc_approve_fixture_is_critical() -> None:
    result = analyze_transaction(load_dump("2026-06-02T09-47"))
    assert result["intent"]["category"] == "ERC20_APPROVAL"
    assert result["intent"]["decodedFunction"] == "approve(address,uint256)"
    assert result["verdict"]["riskLevel"] == "CRITICAL"
    assert result["verdict"]["recommendedAction"] == "REJECT"
    assert {factor["id"] for factor in result["riskFactors"]} >= {"erc20_approval", "known_malicious_spender"}


def test_stringified_transaction_payload_is_decoded_like_object_payload() -> None:
    payload = load_dump("2026-06-02T09-47")
    payload["transaction"] = json.dumps(payload["transaction"])

    result = analyze_transaction(payload)

    assert result["intent"]["category"] == "ERC20_APPROVAL"
    assert result["intent"]["decodedFunction"] == "approve(address,uint256)"
    assert result["evidence"]["calldata"]["selector"] == "0x095ea7b3"
    assert {factor["id"] for factor in result["riskFactors"]} >= {"erc20_approval", "known_malicious_spender"}


def test_eth_dead_transfer_is_high_risk() -> None:
    result = analyze_transaction(load_dump("2026-06-02T11-14"))
    assert result["intent"]["category"] == "NATIVE_TRANSFER"
    assert result["verdict"]["riskLevel"] == "HIGH"
    assert {factor["id"] for factor in result["riskFactors"]} >= {"native_value_transfer", "burn_or_dead_recipient"}


def test_non_evm_is_unsupported() -> None:
    result = analyze_transaction({"chainId": "solana:mainnet", "transaction": {}})
    assert result["intent"]["category"] == "UNSUPPORTED_CHAIN"
    assert result["verdict"]["riskLevel"] == "UNSUPPORTED"


def test_live_without_keys_reports_limitations_not_failure() -> None:
    result = analyze_transaction(load_dump("2026-06-02T11-14"), options=AnalysisOptions(live=True))
    assert result["evidence"]["simulation"]["status"] == "config_missing"
    assert result["evidence"]["providerHealth"]
    assert result["evidence"]["evidenceQuality"]["mode"] == "live-best-effort"
    assert result["verdict"]["riskLevel"] == "HIGH"


def test_simulation_wallet_outflow_fact_affects_risk() -> None:
    class FakeSimulation:
        def simulate(self, chain_id: int, tx: dict) -> dict:
            return {
                "status": "ok",
                "provider": "tenderly",
                "facts": [
                    {
                        "type": "asset_change",
                        "walletDirection": "out",
                        "symbol": "USDT",
                        "amountFormatted": "10",
                        "from": tx["from"].lower(),
                        "to": "0x00000000000000000000000000000000000000bb",
                    }
                ],
            }

    result = analyze_transaction(load_dump("2026-06-02T09-47"), options=AnalysisOptions(mode="live-best-effort"), simulation_adapter=FakeSimulation())
    factor_ids = {factor["id"] for factor in result["riskFactors"]}
    assert "simulation_wallet_asset_outflow" in factor_ids
    assert result["evidence"]["providerHealth"][1]["status"] == "ok"


def test_simulation_outflow_does_not_add_generic_asset_change_factor() -> None:
    class FakeSimulation:
        def simulate(self, chain_id: int, tx: dict) -> dict:
            return {
                "status": "ok",
                "provider": "tenderly",
                "facts": [
                    {"type": "balance_change", "address": "0x00000000000000000000000000000000000000bb"},
                    {
                        "type": "asset_change",
                        "walletDirection": "out",
                        "symbol": "ETH",
                        "amountFormatted": "0.1",
                        "from": tx["from"].lower(),
                        "to": "0x00000000000000000000000000000000000000bb",
                    },
                ],
            }

    result = analyze_transaction(load_dump("2026-06-02T11-14"), options=AnalysisOptions(mode="live-best-effort"), simulation_adapter=FakeSimulation())
    factor_ids = {factor["id"] for factor in result["riskFactors"]}
    assert "simulation_wallet_asset_outflow" not in factor_ids
    assert "simulation_asset_change_present" not in factor_ids


def test_live_native_transfer_to_eoa_is_not_rejected_without_address_risk() -> None:
    recipient = "0x0e2194468c40010656313ce24cee52e934cced03"
    payload = {
        "chainId": "eip155:1",
        "transaction": {
            "from": "0xb7c360aaa4c2b9f727ff934baa6ba300ccc0f284",
            "to": recipient,
            "value": "0x16345785d8a0000",
            "data": "0x",
        },
        "transactionOrigin": "http://127.0.0.1:5173",
    }

    class FakeAddressProfile:
        def inspect(self, chain_id: int, address: str | None) -> dict:
            return {
                "status": "ok",
                "address": address,
                "addressType": "EOA",
                "isContract": False,
                "codeSizeBytes": 0,
            }

    class FakeSimulation:
        def simulate(self, chain_id: int, tx: dict) -> dict:
            return {
                "status": "ok",
                "provider": "tenderly",
                "facts": [
                    {
                        "type": "asset_change",
                        "walletDirection": "out",
                        "symbol": "ETH",
                        "amountFormatted": "0.1",
                        "from": tx["from"].lower(),
                        "to": recipient,
                    }
                ],
            }

    class FakeContractReputation:
        def inspect(self, chain_id: int, address: str | None) -> dict:
            raise AssertionError("EOA recipients should not be inspected as contracts")

    class FakeThreatIntel:
        def inspect(self, chain_id: int, addresses: list[str], origin: str | None) -> dict:
            return {
                "status": "no_matches",
                "matches": [],
                "providers": {
                    "goplusAddress": {
                        "status": "ok",
                        "provider": "goplus_address_security",
                        "matches": [],
                        "addressReports": {recipient: {"malicious_address": "0"}},
                    }
                },
            }

    result = analyze_transaction(
        payload,
        options=AnalysisOptions(mode="production"),
        address_profile_provider=FakeAddressProfile(),
        simulation_adapter=FakeSimulation(),
        contract_adapter=FakeContractReputation(),
        threat_adapter=FakeThreatIntel(),
    )

    factor_ids = {factor["id"] for factor in result["riskFactors"]}
    assert result["evidence"]["addressProfile"]["addressType"] == "EOA"
    assert result["evidence"]["contractReputation"]["status"] == "not_applicable"
    assert "etherscan_source_unverified" not in factor_ids
    assert "simulation_wallet_asset_outflow" not in factor_ids
    assert result["verdict"]["recommendedAction"] == "CONTINUE"


def test_bnb_native_transfer_to_eip7702_delegated_eoa_scans_delegate_contract() -> None:
    recipient = "0x8865c8ff2a1cf8b235143110244f340db8513876"
    delegate = "0x63c0c19a282a1b52b07dd5a65b58948a07dae32b"
    payload = {
        "chainId": "eip155:56",
        "transaction": {
            "from": "0xb7c360aaa4c2b9f727ff934baa6ba300ccc0f284",
            "to": recipient,
            "value": "0x16345785d8a0000",
            "data": "0x",
        },
        "transactionOrigin": "http://127.0.0.1:5173",
    }

    class FakeAddressProfile:
        def inspect(self, chain_id: int, address: str | None) -> dict:
            return {
                "status": "ok",
                "address": address,
                "addressType": "EIP7702_DELEGATED_EOA",
                "isContract": True,
                "isDelegated": True,
                "delegation": {
                    "type": "EIP7702",
                    "indicator": "0xef0100",
                    "delegateAddress": delegate,
                },
                "codeSizeBytes": 23,
            }

    class FakeSimulation:
        def simulate(self, chain_id: int, tx: dict) -> dict:
            return {
                "status": "ok",
                "provider": "tenderly",
                "facts": [
                    {
                        "type": "asset_change",
                        "walletDirection": "out",
                        "symbol": "BNB",
                        "amountFormatted": "0.1",
                        "from": tx["from"].lower(),
                        "to": recipient,
                    }
                ],
            }

    class FakeContractReputation:
        def inspect(self, chain_id: int, address: str | None) -> dict:
            assert address == delegate
            return {
                "status": "ok",
                "address": address,
                "facts": [],
                "etherscan": {
                    "status": "ok",
                    "provider": "etherscan",
                    "sourceVerified": False,
                    "proxy": False,
                    "securitySignals": {},
                    "nametag": {},
                },
                "blockscout": {"status": "config_missing", "provider": "blockscout"},
            }

    class FakeThreatIntel:
        def inspect(self, chain_id: int, addresses: list[str], origin: str | None) -> dict:
            return {
                "status": "no_matches",
                "matches": [],
                "providers": {
                    "goplusAddress": {
                        "status": "ok",
                        "provider": "goplus_address_security",
                        "matches": [],
                        "addressReports": {
                            recipient: {
                                "contract_address": "1",
                                "malicious_address": "0",
                                "phishing_activities": "0",
                                "stealing_attack": "0",
                            }
                        },
                    }
                },
            }

    result = analyze_transaction(
        payload,
        options=AnalysisOptions(mode="production"),
        address_profile_provider=FakeAddressProfile(),
        simulation_adapter=FakeSimulation(),
        contract_adapter=FakeContractReputation(),
        threat_adapter=FakeThreatIntel(),
    )

    factor_ids = {factor["id"] for factor in result["riskFactors"]}
    assert result["evidence"]["addressProfile"]["addressType"] == "EIP7702_DELEGATED_EOA"
    assert result["evidence"]["addressProfile"]["delegation"]["delegateAddress"] == delegate
    assert result["evidence"]["contractReputation"]["address"] == delegate
    assert result["evidence"]["contractReputation"]["recipientAddress"] == recipient
    assert result["evidence"]["contractReputation"]["delegation"]["delegateAddress"] == delegate
    assert "etherscan_source_unverified" in factor_ids
    assert "goplus_address_security_match" not in factor_ids
    assert "simulation_wallet_asset_outflow" not in factor_ids
    assert result["verdict"]["recommendedAction"] == "CONTINUE_WITH_CAUTION"


def test_all_dump_fixtures_analyze_offline() -> None:
    paths = sorted((ROOT / "dump-tx").glob("*.json"))
    assert len(paths) >= 17
    categories = set()
    for path in paths:
        result = analyze_transaction(json.loads(path.read_text(encoding="utf-8")))
        categories.add(result["intent"]["category"])
        assert result["schemaVersion"] == "signshield-risk/v0.2"
        assert result["verdict"]["riskLevel"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert categories >= {
        "ERC20_APPROVAL",
        "NFT_APPROVAL",
        "NATIVE_TRANSFER",
        "TOKEN_TRANSFER",
        "MULTICALL",
        "UNKNOWN_CONTRACT",
    }


def test_eip2612_permit_fixture_decodes_spender_and_unlimited_amount() -> None:
    result = analyze_transaction(load_dump("2026-06-03T00-03"))
    assert result["intent"]["category"] == "ERC20_APPROVAL"
    params = result["evidence"]["calldata"]["parameters"]
    assert params["spender"] == "0x3000000000000000000000000000000000000001"
    assert result["assetImpact"][0]["amount"]["isUnlimited"] is True
    assert {factor["id"] for factor in result["riskFactors"]} >= {"erc20_approval", "large_or_unbounded_allowance", "known_malicious_spender"}


def test_synthetic_attack_fixtures_cover_operator_recipient_and_contract_risks() -> None:
    nft = analyze_transaction(load_dump("2026-06-03T00-04"))
    token_transfer = analyze_transaction(load_dump("2026-06-03T00-06"))
    multicall = analyze_transaction(load_dump("2026-06-03T00-09"))
    unknown = analyze_transaction(load_dump("2026-06-03T00-13"))

    assert "known_malicious_operator" in {factor["id"] for factor in nft["riskFactors"]}
    assert "known_malicious_recipient" in {factor["id"] for factor in token_transfer["riskFactors"]}
    assert "known_malicious_contract" in {factor["id"] for factor in multicall["riskFactors"]}
    assert "known_malicious_contract" in {factor["id"] for factor in unknown["riskFactors"]}


def test_production_mode_does_not_use_fixture_labels_as_malicious_evidence() -> None:
    result = analyze_transaction(load_dump("2026-06-03T00-03"), options=AnalysisOptions(mode="production"))
    factor_ids = {factor["id"] for factor in result["riskFactors"]}
    assert "known_malicious_spender" not in factor_ids
    assert result["evidence"]["evidenceQuality"]["mode"] == "production"


def test_production_mode_guards_unknown_contract_without_live_evidence() -> None:
    result = analyze_transaction(load_dump("2026-06-03T00-13"), options=AnalysisOptions(mode="production"))
    assert result["intent"]["category"] == "UNKNOWN_CONTRACT"
    assert result["verdict"]["recommendedAction"] == "REVIEW_OR_REJECT"
    assert result["verdict"]["evidenceGate"]["guarded"] is True
