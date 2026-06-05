# Airdrop Safety Demo Storyline

This storyline turns the existing TxRiskAgent fixtures into a focused hackathon
demo for:

> Airdrop Claim Pre-Signature Risk Agent

The demo should make one idea obvious: users are not only at risk after a
transaction lands on-chain. They are at risk at the wallet confirmation screen,
when a claim page asks them to sign an approval, Permit, collection-wide NFT
permission, or opaque bundle.

## Demo Goal

Show that TxRiskAgent can inspect a pending wallet action before signing and
answer three questions:

1. What does the user think they are doing?
2. What does the transaction or signature actually do?
3. Should the user sign, reject, reduce allowance, or verify more evidence?

## Setup

Run the deterministic offline analyzer:

```bash
uv run python skills/signshield-risk/scripts/analyze_evm_tx.py dump-tx --output output/risk-reports
```

For the core airdrop demo run, use the six highest-signal fixtures:

```bash
mkdir -p output/risk-reports-airdrop
for fixture in \
  dump-tx/2026-06-03T00-01-00-000Z-erc20-unlimited-approval-phishing.json \
  dump-tx/2026-06-03T00-03-00-000Z-eip2612-permit-unlimited-drainer.json \
  dump-tx/2026-06-03T00-04-00-000Z-nft-setapprovalforall-fake-airdrop.json \
  dump-tx/2026-06-03T00-09-00-000Z-multicall-hidden-approval-and-transfer.json \
  dump-tx/2026-06-03T00-11-00-000Z-universal-router-execute-permit2-style-drain.json \
  dump-tx/2026-06-03T00-12-00-000Z-unknown-claim-rewards-selector.json
do
  uv run python skills/signshield-risk/scripts/analyze_evm_tx.py "$fixture" --output output/risk-reports-airdrop
done
```

Without `uv`, replace the inner command with:

```bash
python3 skills/signshield-risk/scripts/analyze_evm_tx.py "$fixture" --output output/risk-reports-airdrop
```

For a broader airdrop-safety research run, include adjacent cases for excessive
approval, benign revoke, direct token outflow, `transferFrom`, deadline
multicall, address poisoning, and native drainer transfer:

```bash
mkdir -p output/risk-reports-airdrop-extended
for fixture in \
  dump-tx/2026-06-03T00-01-00-000Z-erc20-unlimited-approval-phishing.json \
  dump-tx/2026-06-03T00-02-00-000Z-erc20-large-approval-fake-swap.json \
  dump-tx/2026-06-03T00-03-00-000Z-eip2612-permit-unlimited-drainer.json \
  dump-tx/2026-06-03T00-04-00-000Z-nft-setapprovalforall-fake-airdrop.json \
  dump-tx/2026-06-03T00-05-00-000Z-nft-setapprovalforall-revoke-benign.json \
  dump-tx/2026-06-03T00-06-00-000Z-token-transfer-to-drainer.json \
  dump-tx/2026-06-03T00-08-00-000Z-transferfrom-prior-allowance-drain.json \
  dump-tx/2026-06-03T00-09-00-000Z-multicall-hidden-approval-and-transfer.json \
  dump-tx/2026-06-03T00-10-00-000Z-multicall-deadline-fake-migration.json \
  dump-tx/2026-06-03T00-11-00-000Z-universal-router-execute-permit2-style-drain.json \
  dump-tx/2026-06-03T00-12-00-000Z-unknown-claim-rewards-selector.json \
  dump-tx/2026-06-03T00-14-00-000Z-native-address-poisoning-lookalike.json \
  dump-tx/2026-06-03T00-15-00-000Z-native-transfer-to-synthetic-drainer.json
do
  uv run python skills/signshield-risk/scripts/analyze_evm_tx.py "$fixture" --output output/risk-reports-airdrop-extended
done
```

## Three-Act Demo

### Act 1: Fake Token Claim

Fixture:

```text
dump-tx/2026-06-03T00-01-00-000Z-erc20-unlimited-approval-phishing.json
```

Presenter line:

> The page says "Claim rewards", but SignShield decodes the pending transaction
> before the user signs.

Expected analyzer result:

- `intent.category`: `ERC20_APPROVAL`
- `intent.decodedFunction`: `approve(address,uint256)`
- `assetImpact[0].amount.isUnlimited`: `true`
- `verdict.riskLevel`: `CRITICAL`
- `verdict.recommendedAction`: `REJECT`

Plain-language reveal:

> This is not a claim. It grants another address unlimited permission to spend
> the user's token.

Why it lands:

- Everyone understands "claim reward".
- The decoded function proves the mismatch.
- The recommendation is decisive.

### Act 2: Gasless Claim That Is Actually Permit

Fixture:

```text
dump-tx/2026-06-03T00-03-00-000Z-eip2612-permit-unlimited-drainer.json
```

Presenter line:

> Scammers often call this "gasless claim" because users associate no gas with
> low risk. But a signature can still grant spending rights.

Expected analyzer result:

- `intent.category`: `ERC20_APPROVAL`
- `intent.decodedFunction`: `permit(address,address,uint256,uint256,uint8,bytes32,bytes32)`
- `assetImpact[0].spender`: fixture drainer address
- `assetImpact[0].amount.isUnlimited`: `true`
- `verdict.riskLevel`: `CRITICAL`

Plain-language reveal:

> Gasless does not mean harmless. This Permit gives a spender permission to move
> the user's token.

Why it lands:

- It explains an unintuitive Web3 risk.
- It shows why pre-signature decoding must cover signatures and Permit-style
  approvals, not only normal on-chain transfers.

### Act 3: NFT Airdrop Verify

Fixture:

```text
dump-tx/2026-06-03T00-04-00-000Z-nft-setapprovalforall-fake-airdrop.json
```

Presenter line:

> The page asks the user to verify their wallet for an NFT airdrop. The wallet
> request is actually collection-wide operator approval.

Expected analyzer result:

- `intent.category`: `NFT_APPROVAL`
- `intent.decodedFunction`: `setApprovalForAll(address,bool)`
- `assetImpact[0].type`: `NFT_OPERATOR_APPROVAL`
- `assetImpact[0].amount.formatted`: `all NFTs in collection`
- `verdict.riskLevel`: `CRITICAL`

Plain-language reveal:

> This gives another address permission to transfer all NFTs in the collection.

Why it lands:

- NFT users know the phrase "verify wallet".
- The asset impact is simple and frightening in the right way: all NFTs in a
  collection can be moved.

## Optional Technical Deepening

Use these if the judges ask what is hard or what comes next.

### Multicall Hidden Approval and Transfer

Fixture:

```text
dump-tx/2026-06-03T00-09-00-000Z-multicall-hidden-approval-and-transfer.json
```

Point to make:

- Bundled calls hide multiple actions under one wallet prompt.
- The current analyzer flags this as critical but low-confidence because full
  recursive decoding is a future milestone.

Demo phrase:

> When the claim is wrapped in `multicall`, missing child-call visibility is
> itself a risk signal. We should not turn "I cannot see it" into "it is safe".

### Router / Permit2-Style Bundle

Fixture:

```text
dump-tx/2026-06-03T00-11-00-000Z-universal-router-execute-permit2-style-drain.json
```

Point to make:

- Router-style flows can compress Permit2, route execution, transfer, and
  deadline checks into one signing surface.
- This is where external simulation and recursive decode add value.

### Unknown Claim Selector

Fixture:

```text
dump-tx/2026-06-03T00-12-00-000Z-unknown-claim-rewards-selector.json
```

Point to make:

- Unknown selectors should be framed as "opaque claim risk".
- The user should verify the official link, contract source, and simulation
  result before signing.

## One-Slide Product Summary

Problem:

- Airdrop scams disguise approvals and transfers as claim actions.

Approach:

- Decode calldata/signature facts.
- Simulate or infer asset and permission changes.
- Check contract, domain, spender, and token risk signals.
- Explain the mismatch before signing.

Core output:

- Risk level
- Actual intent
- Asset impact
- Evidence chain
- Recommended action

Demo takeaway:

> SignShield does not need to know whether an airdrop is real. It needs to know
> whether the thing the user is about to sign can move or expose their assets.

## Suggested Next Code Milestones

1. Add explicit `claimedIntent`, `actualIntent`, and `intentMismatch` fields for
   claim-like origins.
2. Improve Permit and Permit2 user-facing copy so "gasless" is clearly separated
   from "safe".
3. Recursively decode `multicall(bytes[])`, `multicall(uint256,bytes[])`, and
   router-style `execute` payloads when ABI layout is known.
4. Raise unknown claim-like selectors from generic caution into an
   airdrop-specific opaque-claim warning when origin or page context indicates
   `claim`, `airdrop`, `rewards`, `gasless`, or `verify`.
