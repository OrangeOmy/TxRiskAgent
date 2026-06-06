from __future__ import annotations

from typing import Any

from .adapters import (
    CombinedCalldataResolver,
    CompositeContractReputationAdapter,
    CompositeThreatIntelAdapter,
    FourByteDirectoryResolver,
    SourcifyOpenChainResolver,
    TenderlySimulationAdapter,
)
from .adapters.http import HttpClient
from .decode import decode_calldata
from .contract_bytecode_scanner import scan_contract_bytecode
from .decision import build_decision, confidence_for
from .erc20_scoring import apply_erc20_token_profile_rules
from .evidence import EvidenceOrchestrator, resolve_mode
from .fixtures import ADDRESS_FIXTURES, TOKEN_FIXTURES
from .rules import RuleContext, default_rule_engine
from .subagent_context_builder import build_subagent_context
from .subagent_harness import apply_subagent_recommended_factors, run_subagent_harness
from .token_metadata import TokenMetadataResolver
from .token_security_normalizer import build_erc20_token_risk_profile
from .types import AnalysisOptions, CalldataResolver, ContractReputationAdapter, SimulationAdapter, SubagentClient, ThreatIntelAdapter, TokenMetadataProvider
from .utils import (
    DEAD_ADDRESSES,
    UNLIMITED_THRESHOLD,
    add_factor,
    format_units,
    hex_to_int,
    normalize_address,
    normalize_chain,
)


def build_default_adapters(options: AnalysisOptions) -> dict[str, Any]:
    if not options.live:
        return {}
    client = HttpClient(timeout=options.timeout)
    resolver = CombinedCalldataResolver([SourcifyOpenChainResolver(client=client), FourByteDirectoryResolver(client=client)])
    simulation = TenderlySimulationAdapter(options.tenderly_account, options.tenderly_project, options.tenderly_access_key, client=client)
    contract = CompositeContractReputationAdapter(options.etherscan_api_key, options.blockscout_base_url, client=client)
    threat = CompositeThreatIntelAdapter(options.goplus_base_url, options.metamask_config_url, client=client)
    return {
        "calldata_resolver": resolver,
        "simulation_adapter": simulation,
        "contract_adapter": contract,
        "threat_adapter": threat,
    }


def analyze_transaction(
    payload: dict[str, Any],
    input_ref: str = "<memory>",
    *,
    options: AnalysisOptions | None = None,
    calldata_resolver: CalldataResolver | None = None,
    simulation_adapter: SimulationAdapter | None = None,
    contract_adapter: ContractReputationAdapter | None = None,
    threat_adapter: ThreatIntelAdapter | None = None,
    token_metadata_provider: TokenMetadataProvider | None = None,
    subagent_client: SubagentClient | None = None,
) -> dict[str, Any]:
    options = options or AnalysisOptions()
    mode = resolve_mode(options)
    allow_fixture_risk = options.allow_fixture_risk and mode != "production"

    tx = payload.get("transaction") if isinstance(payload.get("transaction"), dict) else payload
    origin = payload.get("transactionOrigin") or payload.get("origin")
    chain = normalize_chain(payload.get("chainId") or tx.get("chainId"))

    if not chain.supported:
        return unsupported_result(input_ref, chain.raw)

    from_addr = normalize_address(tx.get("from"))
    to_addr = normalize_address(tx.get("to"))
    data = tx.get("data") if isinstance(tx.get("data"), str) else "0x"
    value_wei = hex_to_int(tx.get("value"), 0)
    initial_decoded = decode_calldata(data, calldata_resolver)
    initial_category, _ = classify_intent(initial_decoded, value_wei)
    addresses = collect_addresses(from_addr, to_addr, initial_decoded)
    erc20_token_address = erc20_token_target(initial_category, to_addr)
    orchestrator = EvidenceOrchestrator(
        options,
        calldata_resolver=calldata_resolver,
        simulation_adapter=simulation_adapter,
        contract_adapter=contract_adapter,
        threat_adapter=threat_adapter,
        token_metadata_provider=token_metadata_provider,
    )
    evidence = orchestrator.collect(
        chain_id=chain.chain_id,
        data=data,
        tx=tx,
        to_addr=to_addr,
        addresses=addresses,
        origin=origin,
        erc20_token_address=erc20_token_address,
    )
    decoded = evidence.decoded
    category, intent_description = classify_intent(decoded, value_wei)
    if erc20_token_address is None:
        erc20_token_address = erc20_token_target(category, to_addr)
    simulation = evidence.simulation
    contract_rep = evidence.contract_reputation
    threat_intel = evidence.threat_intel
    bytecode_scan = evidence.bytecode_scan
    erc20_profile = evidence.erc20_profile
    limitations = []

    if simulation.get("status") in {"not_run", "config_missing"}:
        limitations.append("No live transaction simulation was executed.")
    if contract_rep.get("status") in {"not_run", "config_missing", "limited"}:
        limitations.append("Live source verification, proxy, deployment age, or label data may be incomplete.")
    if threat_intel.get("status") in {"not_run", "config_missing"}:
        limitations.append("No live third-party threat intelligence was queried.")

    intent = {"category": category, "description": intent_description, "decodedFunction": decoded.get("function")}
    chain_evidence = {"raw": chain.raw, "chainId": chain.chain_id, "caip2": chain.caip2, "name": chain.name}
    context = RuleContext(
        mode=mode,
        chain=chain_evidence,
        tx=tx,
        origin=origin,
        from_addr=from_addr,
        to_addr=to_addr,
        value_wei=value_wei,
        decoded=decoded,
        intent=intent,
        simulation=simulation,
        contract_reputation=contract_rep,
        threat_intel=threat_intel,
        erc20_profile=erc20_profile,
        provider_health=evidence.provider_health,
        evidence_quality=evidence.evidence_quality,
        allow_fixture_risk=allow_fixture_risk,
    )
    rule_result = default_rule_engine().evaluate(context)
    impacts = rule_result.asset_impacts
    factors = rule_result.risk_factors
    limitations.extend(rule_result.limitations)

    subagent_result: dict[str, Any] | None = None
    if should_run_subagent(options.subagent_mode, category, factors, erc20_profile, simulation, origin):
        pre_subagent_verdict = build_decision(
            category=category,
            decoded=decoded,
            simulation=simulation,
            contract_reputation=contract_rep,
            threat_intel=threat_intel,
            factors=factors,
            evidence_quality=evidence.evidence_quality,
            mode=mode,
        )
        subagent_context = build_subagent_context(
            chain=chain_evidence,
            token_address=erc20_token_address,
            origin=origin,
            intent=intent,
            decoded=decoded,
            token_profile=erc20_profile or {},
            bytecode_scan=bytecode_scan,
            contract_reputation=contract_rep,
            threat_intel=threat_intel,
            simulation=simulation,
            deterministic_risk_factors=factors,
            provider_health=evidence.provider_health,
            evidence_quality=evidence.evidence_quality,
            verdict_pre_subagent=pre_subagent_verdict,
            tasks=subagent_tasks(category, erc20_profile, simulation, origin),
        )
        subagent_result = run_subagent_harness(
            options.subagent_mode,
            subagent_context,
            command=options.subagent_command,
            client=subagent_client,
        )
        if erc20_profile is not None:
            erc20_profile["subagentAssessments"] = subagent_result.get("assessments", [])
            erc20_profile["subagent"] = subagent_result
        apply_subagent_recommended_factors(subagent_result, factors)
        if subagent_result.get("limitations"):
            limitations.extend(subagent_result["limitations"])

    verdict = build_decision(
        category=category,
        decoded=decoded,
        simulation=simulation,
        contract_reputation=contract_rep,
        threat_intel=threat_intel,
        factors=factors,
        evidence_quality=evidence.evidence_quality,
        mode=mode,
    )

    return {
        "schemaVersion": "signshield-risk/v0.2",
        "inputRef": input_ref,
        "verdict": {
            "riskLevel": verdict["riskLevel"],
            "score": verdict["score"],
            "confidence": verdict["confidence"],
            "recommendedAction": verdict["recommendedAction"],
            "evidenceGate": verdict["evidenceGate"],
        },
        "summary": build_summary(category, verdict["riskLevel"], impacts, factors),
        "intent": intent,
        "assetImpact": impacts,
        "riskFactors": factors,
        "evidence": {
            "chain": chain_evidence,
            "calldata": decoded,
            "simulation": simulation,
            "contractReputation": contract_rep,
            "threatIntel": threat_intel,
            "erc20TokenRisk": erc20_profile,
            "subagent": subagent_result,
            "providerHealth": evidence.provider_health,
            "evidenceQuality": evidence.evidence_quality,
            "limitations": limitations,
        },
        "recommendation": build_recommendation(verdict["recommendedAction"], category, factors),
    }


def unsupported_result(input_ref: str, raw_chain: Any) -> dict[str, Any]:
    return {
        "schemaVersion": "signshield-risk/v0.2",
        "inputRef": input_ref,
        "verdict": {
            "riskLevel": "UNSUPPORTED",
            "score": 0,
            "confidence": "HIGH",
            "recommendedAction": "UNSUPPORTED",
        },
        "summary": "当前版本只分析 EVM 链交易；该输入不是 eip155 链，未进行风险判断。",
        "intent": {"category": "UNSUPPORTED_CHAIN", "description": "非 EVM 链输入。", "decodedFunction": None},
        "assetImpact": [],
        "riskFactors": [],
        "evidence": {
            "chain": {"raw": raw_chain, "supported": False},
            "calldata": {},
            "simulation": {},
            "contractReputation": {},
            "threatIntel": {},
            "limitations": ["Only EVM eip155 chains are supported."],
        },
        "recommendation": "请使用支持该链的专用分析模块。",
    }


def classify_intent(decoded: dict[str, Any], value_wei: int) -> tuple[str, str]:
    fn = decoded.get("function")
    if decoded.get("isEmpty") and value_wei > 0:
        return "NATIVE_TRANSFER", "这是一笔原生币转账，交易本身不调用智能合约函数。"
    if fn == "approve(address,uint256)" or (fn and "permit" in fn.lower()):
        return "ERC20_APPROVAL", "这笔交易会授予第三方地址花费该 ERC20 代币的权限。"
    if fn == "setApprovalForAll(address,bool)":
        return "NFT_APPROVAL", "这笔交易会设置 NFT collection 的全集操作权限。"
    if fn in {"transfer(address,uint256)", "transferFrom(address,address,uint256)"}:
        return "TOKEN_TRANSFER", "这笔交易会转移代币或请求通过既有授权转移代币。"
    if fn and ("multicall" in fn or fn.startswith("execute(")):
        return "MULTICALL", "这笔交易会执行聚合调用，内部可能包含多步资产或权限变化。"
    return "UNKNOWN_CONTRACT", "当前 calldata 无法被标准选择器库完整识别，需要依赖模拟和合约信誉补充判断。"


def token_metadata(chain_id: int | None, address: str | None) -> dict[str, Any]:
    if chain_id is None or address is None:
        return {"chainId": None, "address": address, "symbol": "UNKNOWN", "decimals": 18}
    fixture = TOKEN_FIXTURES.get((chain_id, address.lower()))
    if fixture:
        return {"chainId": f"eip155:{chain_id}", "address": address, **fixture}
    return {"chainId": f"eip155:{chain_id}", "address": address, "symbol": "UNKNOWN_ERC20", "decimals": 18}


def erc20_token_target(category: str, to_addr: str | None) -> str | None:
    if category in {"ERC20_APPROVAL", "TOKEN_TRANSFER"}:
        return to_addr
    return None


def should_run_subagent(
    subagent_mode: str,
    category: str,
    factors: list[dict[str, Any]],
    erc20_profile: dict[str, Any] | None,
    simulation: dict[str, Any],
    origin: str | None,
) -> bool:
    if subagent_mode == "off":
        return False
    if erc20_profile is not None:
        return True
    if category in {"MULTICALL", "UNKNOWN_CONTRACT"}:
        return True
    if simulation.get("status") == "ok" and simulation.get("facts"):
        return True
    if origin and any(factor.get("id") in {"large_or_unbounded_allowance", "nft_collection_wide_approval"} for factor in factors):
        return True
    return False


def subagent_tasks(category: str, erc20_profile: dict[str, Any] | None, simulation: dict[str, Any], origin: str | None) -> list[str]:
    tasks = []
    if erc20_profile is not None:
        tasks.extend(["source_semantic_privilege_review", "complex_honeypot_soft_rug_review"])
    if origin:
        tasks.append("protocol_domain_mismatch_review")
    if simulation.get("status") == "ok" and simulation.get("facts"):
        tasks.append("simulation_trace_attack_path_review")
    if category in {"MULTICALL", "UNKNOWN_CONTRACT"}:
        tasks.append("unknown_or_multicall_intent_review")
    return tasks or ["protocol_domain_mismatch_review"]


def collect_addresses(*values: Any) -> list[str]:
    addresses: set[str] = set()
    for value in values:
        if isinstance(value, str):
            normalized = normalize_address(value)
            if normalized:
                addresses.add(normalized)
        elif isinstance(value, dict):
            for nested in value.values():
                if isinstance(nested, str):
                    normalized = normalize_address(nested)
                    if normalized:
                        addresses.add(normalized)
    return sorted(addresses)


def apply_branch_rules(
    category: str,
    chain_id: int,
    caip2: str | None,
    tx: dict[str, Any],
    decoded: dict[str, Any],
    value_wei: int,
    from_addr: str | None,
    to_addr: str | None,
    impacts: list[dict[str, Any]],
    factors: list[dict[str, Any]],
    *,
    allow_fixture_risk: bool = True,
) -> None:
    if category == "NATIVE_TRANSFER":
        formatted_native = format_units(value_wei, 18)
        impacts.append(
            {
                "type": "NATIVE_TRANSFER",
                "asset": {"chainId": caip2, "address": None, "symbol": "ETH" if chain_id == 1 else "NATIVE", "decimals": 18},
                "amount": {"raw": tx.get("value", hex(value_wei)), "formatted": formatted_native, "isUnlimited": False},
                "from": from_addr,
                "to": to_addr,
            }
        )
        add_factor(factors, "native_value_transfer", "technical", "MEDIUM", 20, "原生币会离开钱包", f"签名后将从当前账户转出 {formatted_native} 个原生币到 {to_addr}。", {"valueWei": str(value_wei), "recipient": to_addr})
        if to_addr in DEAD_ADDRESSES:
            add_factor(factors, "burn_or_dead_recipient", "technical", "HIGH", 45, "收款地址是 burn/dead 地址", "收款人是常见销毁地址，转出的资产通常不可找回。", {"recipient": to_addr})
        if allow_fixture_risk:
            add_local_address_fixture_factor(factors, chain_id, to_addr, "known_malicious_recipient", "scam_phishing", "CRITICAL", 60, "收款地址命中本地风险样例", "recipient")
        return

    if category == "ERC20_APPROVAL":
        params = decoded["parameters"]
        spender = params.get("spender")
        amount_raw = int(params.get("amountRaw") or 0)
        token = token_metadata(chain_id, to_addr)
        formatted = format_units(amount_raw, int(token.get("decimals") or 18))
        is_unlimited = amount_raw >= UNLIMITED_THRESHOLD
        impacts.append(
            {
                "type": "ERC20_APPROVAL",
                "asset": token,
                "amount": {"raw": hex(amount_raw), "formatted": formatted, "isUnlimited": is_unlimited},
                "from": from_addr,
                "spender": spender,
            }
        )
        add_factor(factors, "erc20_approval", "technical", "MEDIUM", 25, "ERC20 花费授权", f"该交易会允许 spender {spender} 花费你的 {token['symbol']}，授权数量为 {formatted}。", {"spender": spender, "token": to_addr, "amountRaw": str(amount_raw)})
        if is_unlimited or amount_raw >= 10**24:
            add_factor(factors, "large_or_unbounded_allowance", "technical", "HIGH", 30, "授权额度很大或接近无限", "授权额度远高于一次普通操作需要的数量；spender 后续可能在授权有效期内继续转走代币。", {"amountRaw": str(amount_raw), "isUnlimited": is_unlimited})
        fixture = ADDRESS_FIXTURES.get((chain_id, spender or ""))
        if fixture and allow_fixture_risk:
            add_factor(factors, "known_malicious_spender", "scam_phishing", "CRITICAL", 60, "spender 命中本地恶意代理样例", fixture["summary"], {"spender": spender, "source": fixture["source"], "label": fixture["label"]})
        return

    if category == "NFT_APPROVAL":
        params = decoded["parameters"]
        operator = params.get("operator")
        approved = bool(params.get("approved"))
        impacts.append(
            {
                "type": "NFT_OPERATOR_APPROVAL",
                "asset": {"chainId": caip2, "address": to_addr, "symbol": "NFT_COLLECTION", "decimals": 0},
                "amount": {"raw": "all", "formatted": "all NFTs in collection" if approved else "revoked", "isUnlimited": approved},
                "from": from_addr,
                "operator": operator,
            }
        )
        if approved:
            add_factor(factors, "nft_collection_wide_approval", "technical", "HIGH", 40, "NFT 全集授权", f"operator {operator} 将获得转移该 collection 下所有 NFT 的权限。", {"operator": operator, "collection": to_addr})
            if allow_fixture_risk:
                add_local_address_fixture_factor(factors, chain_id, operator, "known_malicious_operator", "scam_phishing", "CRITICAL", 60, "NFT operator 命中本地风险样例", "operator")
        return

    if category == "TOKEN_TRANSFER":
        params = decoded["parameters"]
        token = token_metadata(chain_id, to_addr)
        amount_raw = int(params.get("amountRaw") or 0)
        recipient = params.get("to")
        formatted = format_units(amount_raw, int(token.get("decimals") or 18))
        impacts.append(
            {
                "type": "TOKEN_TRANSFER",
                "asset": token,
                "amount": {"raw": hex(amount_raw), "formatted": formatted, "isUnlimited": False},
                "from": params.get("from") or from_addr,
                "to": recipient,
            }
        )
        add_factor(factors, "token_transfer", "technical", "MEDIUM", 25, "代币会被转出", f"该交易会转出 {formatted} {token['symbol']} 到 {recipient}。", {"recipient": recipient, "amountRaw": str(amount_raw)})
        if recipient in DEAD_ADDRESSES:
            add_factor(factors, "burn_or_dead_recipient", "technical", "HIGH", 45, "收款地址是 burn/dead 地址", "代币接收方是常见销毁地址，转出的资产通常不可找回。", {"recipient": recipient})
        if allow_fixture_risk:
            add_local_address_fixture_factor(factors, chain_id, recipient, "known_malicious_recipient", "scam_phishing", "CRITICAL", 60, "代币接收地址命中本地风险样例", "recipient")
        return

    if category == "MULTICALL":
        if allow_fixture_risk:
            add_local_address_fixture_factor(factors, chain_id, to_addr, "known_malicious_contract", "scam_phishing", "CRITICAL", 60, "聚合调用目标命中本地风险样例", "contract")
        add_factor(factors, "multicall_requires_recursive_decode", "uncertainty", "MEDIUM", 25, "聚合调用需要递归解析", "当前识别到聚合执行入口，但尚未递归解析内部调用。", {"selector": decoded.get("selector"), "function": decoded.get("function")})
        return

    if allow_fixture_risk:
        add_local_address_fixture_factor(factors, chain_id, to_addr, "known_malicious_contract", "scam_phishing", "CRITICAL", 60, "目标合约命中本地风险样例", "contract")
    add_factor(factors, "unknown_selector_or_contract", "uncertainty", "MEDIUM", 25, "交易意图无法完整识别", "当前选择器库无法完整解释该 calldata，缺少模拟和合约透明度事实时不应视为安全。", {"selector": decoded.get("selector"), "to": to_addr})


def add_local_address_fixture_factor(
    factors: list[dict[str, Any]],
    chain_id: int,
    address: str | None,
    factor_id: str,
    domain: str,
    severity: str,
    score: int,
    title: str,
    target_key: str,
) -> None:
    if not address:
        return
    fixture = ADDRESS_FIXTURES.get((chain_id, address.lower()))
    if not fixture:
        return
    add_factor(
        factors,
        factor_id,
        domain,
        severity,
        score,
        title,
        fixture["summary"],
        {target_key: address, "source": fixture["source"], "label": fixture["label"]},
    )


def apply_contract_reputation_rules(contract_rep: dict[str, Any], factors: list[dict[str, Any]], *, allow_fixture_risk: bool = True) -> None:
    for fact in contract_rep.get("facts", []):
        if fact.get("risk") == "known_malicious_proxy" and allow_fixture_risk:
            add_factor(factors, "known_malicious_spender", "scam_phishing", "CRITICAL", 60, "spender 命中恶意代理样例", fact["summary"], {"spender": fact.get("address"), "source": fact.get("source"), "label": fact.get("label")})
    for source_key in ("etherscan", "blockscout"):
        source = contract_rep.get(source_key)
        if not isinstance(source, dict) or source.get("status") != "ok":
            continue
        if source.get("sourceVerified") is False:
            add_factor(factors, f"{source_key}_source_unverified", "technical", "MEDIUM", 20, "合约源码未验证", f"{source_key} 未返回已验证源码。", {"provider": source_key})
        if source.get("proxy") and not source.get("implementation"):
            add_factor(factors, f"{source_key}_proxy_without_implementation", "technical", "HIGH", 25, "Proxy implementation 不明确", f"{source_key} 显示该合约是 proxy，但未返回 implementation。", {"provider": source_key})
        if source.get("proxy") and source.get("implementationVerified") is False:
            add_factor(factors, f"{source_key}_proxy_implementation_unverified", "technical", "HIGH", 35, "Proxy implementation 未验证", f"{source_key} 显示该合约是 proxy，且 implementation 未验证。", {"provider": source_key, "implementation": source.get("implementation")})
        age_days = source.get("ageDays")
        if isinstance(age_days, int) and age_days <= 7:
            add_factor(factors, f"{source_key}_newly_deployed_contract", "uncertainty", "MEDIUM", 20, "合约部署时间很短", f"{source_key} 显示该合约部署不足 7 天，历史行为样本有限。", {"provider": source_key, "ageDays": age_days, "deployedAt": source.get("deployedAt")})
        nametag = source.get("nametag") if isinstance(source.get("nametag"), dict) else {}
        labels = [str(label).lower() for label in (nametag.get("labelsSlug") or nametag.get("labels") or [])]
        label_text = " ".join(labels)
        if any(marker in label_text for marker in ("phish", "hack", "scam", "drainer", "ofac", "sanction")):
            add_factor(factors, f"{source_key}_address_security_label", "scam_phishing", "CRITICAL", 70, "Etherscan 地址标签命中安全风险", f"{source_key} nametag/label 显示该地址存在安全或合规风险。", {"provider": source_key, "nametag": nametag.get("nametag"), "labels": nametag.get("labels"), "labelsSlug": nametag.get("labelsSlug")})
        security_signals = source.get("securitySignals") if isinstance(source.get("securitySignals"), dict) else {}
        if _source_signal_present(security_signals, "selfdestructPresent"):
            add_factor(factors, f"{source_key}_source_selfdestruct_signal", "technical", "HIGH", 40, "源码出现 selfdestruct 能力", f"{source_key} 已验证源码或 ABI 中出现 selfdestruct/suicide 风险信号。", {"provider": source_key})
        if _source_signal_present(security_signals, "externalCallPresent") and source.get("sourceVerified") is False:
            add_factor(factors, f"{source_key}_unverified_external_call_signal", "technical", "HIGH", 35, "未验证合约存在外部调用信号", f"{source_key} 显示合约未验证，且存在外部调用相关风险信号。", {"provider": source_key})
        privileged = security_signals.get("privilegedFunctionNames")
        if isinstance(privileged, list) and len(privileged) >= 5:
            add_factor(factors, f"{source_key}_many_privileged_functions", "technical", "MEDIUM", 25, "合约包含多个特权函数", f"{source_key} ABI/source 显示该合约存在多个 owner/admin 风格的控制函数。", {"provider": source_key, "functions": privileged[:20]})


def _source_signal_present(security_signals: dict[str, Any], key: str) -> bool:
    signal = security_signals.get(key)
    return isinstance(signal, dict) and bool(signal.get("present"))


def apply_threat_intel_rules(threat_intel: dict[str, Any], factors: list[dict[str, Any]], *, allow_fixture_risk: bool = True) -> None:
    for match in threat_intel.get("matches", []):
        if match.get("type") == "domain_phishing":
            add_factor(factors, "phishing_domain_match", "scam_phishing", "CRITICAL", 50, "来源域名命中钓鱼列表", "交易来源命中 MetaMask eth-phishing-detect。", match)
        elif match.get("type") == "token_security":
            add_factor(factors, "goplus_token_security_flags", "technical", "HIGH", 30, "GoPlus 返回 token 风险标记", "GoPlus Token Security API 返回高风险 token 标记。", match)
        elif match.get("risk") == "known_malicious_proxy" and allow_fixture_risk:
            add_factor(factors, "known_malicious_spender", "scam_phishing", "CRITICAL", 60, "地址命中本地恶意代理样例", match.get("summary", "本地样例标记该地址存在恶意风险。"), match)


def apply_simulation_rules(simulation: dict[str, Any], factors: list[dict[str, Any]]) -> None:
    simulation_facts = simulation.get("facts", [])
    has_wallet_outflow = any(
        fact.get("type") in {"asset_change", "balance_change"} and fact.get("walletDirection") == "out"
        for fact in simulation_facts
        if isinstance(fact, dict)
    )
    for fact in simulation_facts:
        if fact.get("type") == "revert_or_error":
            add_factor(factors, "simulation_revert_or_error", "uncertainty", "MEDIUM", 20, "交易模拟失败或 revert", "模拟返回失败或错误，不能把缺失结果视为安全。", fact, "live_provider")
        elif fact.get("type") in {"asset_change", "balance_change"} and fact.get("walletDirection") == "out":
            amount = fact.get("amountFormatted") or fact.get("amountRaw") or "unknown amount"
            symbol = fact.get("symbol") or fact.get("tokenAddress") or "asset"
            add_factor(
                factors,
                "simulation_wallet_asset_outflow",
                "technical",
                "HIGH",
                35,
                "模拟显示钱包资产流出",
                f"Tenderly 模拟显示当前钱包会流出 {amount} {symbol}，需要确认这是否符合预期。",
                fact,
                "live_provider",
            )
        elif fact.get("type") == "approval_change" and fact.get("walletOwner") is True:
            add_factor(
                factors,
                "simulation_approval_change",
                "technical",
                "MEDIUM",
                25,
                "模拟显示授权状态变化",
                "Tenderly 模拟显示当前钱包的授权状态会发生变化，需要确认 spender 和额度。",
                fact,
                "live_provider",
            )
        elif fact.get("type") in {"asset_change", "balance_change"} and not has_wallet_outflow:
            add_factor(factors, "simulation_asset_change_present", "technical", "MEDIUM", 20, "模拟显示资产变化", "交易模拟返回了资产或余额变化，需要与用户预期核对。", {"type": fact.get("type")}, "live_provider")


def confidence_for(category: str, decoded: dict[str, Any], simulation: dict[str, Any], contract_rep: dict[str, Any], threat_intel: dict[str, Any], factors: list[dict[str, Any]]) -> str:
    factor_ids = {factor["id"] for factor in factors}
    if "known_malicious_spender" in factor_ids or threat_intel.get("matches"):
        return "HIGH"
    if simulation.get("status") == "ok" and decoded.get("function"):
        return "HIGH"
    if category in {"NATIVE_TRANSFER", "ERC20_APPROVAL", "NFT_APPROVAL", "TOKEN_TRANSFER"} and decoded.get("function") is not None or category == "NATIVE_TRANSFER":
        return "HIGH"
    if contract_rep.get("status") == "ok":
        return "MEDIUM"
    return "LOW"


def build_summary(category: str, level: str, impacts: list[dict[str, Any]], factors: list[dict[str, Any]]) -> str:
    factor_titles = "；".join(factor["title"] for factor in factors[:3])
    if category == "ERC20_APPROVAL" and impacts:
        impact = impacts[0]
        asset = impact["asset"]["symbol"]
        spender = impact.get("spender")
        amount = impact["amount"]["formatted"]
        return f"{level} 风险：这不是普通页面确认，而是在授权 {spender} 花费你的 {asset}，额度为 {amount}。主要风险：{factor_titles}。"
    if category == "NATIVE_TRANSFER" and impacts:
        impact = impacts[0]
        amount = impact["amount"]["formatted"]
        recipient = impact.get("to")
        return f"{level} 风险：这笔交易会把 {amount} 个原生币发送到 {recipient}。主要风险：{factor_titles}。"
    if category == "NFT_APPROVAL":
        return f"{level} 风险：这笔交易涉及 NFT 全集操作权限。主要风险：{factor_titles}。"
    if category == "TOKEN_TRANSFER":
        return f"{level} 风险：这笔交易会转移代币资产。主要风险：{factor_titles}。"
    if category == "MULTICALL":
        return f"{level} 风险：这笔交易是聚合调用，当前版本尚未展开所有内部动作。主要风险：{factor_titles}。"
    return f"{level} 风险：当前版本无法完整解释该交易意图。主要风险：{factor_titles}。"


def build_recommendation(action: str, category: str, factors: list[dict[str, Any]]) -> str:
    factor_ids = {factor["id"] for factor in factors}
    if action == "REJECT":
        if "known_malicious_spender" in factor_ids:
            return "建议拒绝签名。spender 已命中恶意代理样例，继续授权可能导致代币被转走。"
        return "建议拒绝这笔交易，除非你能独立确认收款人、合约和资产影响完全符合预期。"
    if action == "REDUCE_ALLOWANCE":
        return "建议不要直接确认。将授权额度降低到本次操作所需的最小值，或改用 burner wallet。"
    if action == "CONTINUE_WITH_CAUTION":
        return "可以谨慎继续，但应先确认 dApp 来源、合约地址和资产影响与预期一致。"
    if action == "UNSUPPORTED":
        return "请使用对应链的专用风险分析模块。"
    return "未发现高风险信号；仍建议确认收款地址和交易金额。"
