# Airdrop Security Cases

This document narrows the TxRiskAgent demo corpus into an airdrop-specific
research set. The product question is not "does this airdrop exist?" The safer
question is:

> Before the user signs, does the claimed `claim` action actually grant
> spending rights, move assets, or hide behavior behind an opaque call?

The cases below are synthetic offline fixtures from `dump-tx/`. Do not broadcast
them or interact with any fixture address.

## Fixture Numbering

The labels `00-01`, `00-03`, and similar names are shorthand for the synthetic
fixtures listed in `dump-tx/description.txt`. They come from the timestamped
file names:

```text
2026-06-03T00-01-00-000Z-erc20-unlimited-approval-phishing.json
2026-06-03T00-03-00-000Z-eip2612-permit-unlimited-drainer.json
...
```

They are not on-chain transaction ids. They are local test cases that model
different pre-signature risk branches.

## Core Case Matrix

Use these six cases for the main airdrop claim demo. They are intentionally
small enough to present in a few minutes while still covering the dominant
attack paths: approval, Permit, NFT operator approval, bundles, router-style
execution, and unknown selectors.

| Case | Claimed user action | Actual pre-signature behavior | Primary branch | Demo value |
| --- | --- | --- | --- | --- |
| `00-01` | Claim token rewards | ERC20 unlimited `approve` | `ERC20_APPROVAL` | Most direct fake-airdrop drainer pattern |
| `00-03` | Gasless claim | EIP-2612 `permit` approval | `ERC20_APPROVAL` | Shows that "no gas" can still grant asset rights |
| `00-04` | Verify NFT airdrop | `setApprovalForAll(true)` | `NFT_APPROVAL` | Clear NFT collection-wide permission risk |
| `00-09` | Claim through a bundled flow | `multicall(bytes[])` with hidden approval/transfer payload | `MULTICALL` | Explains why wallet popups often miss nested intent |
| `00-11` | Claim through router / Permit2-style flow | Universal Router-style `execute` bundle | `MULTICALL` | Covers router and Permit2-style pre-signature risk |
| `00-12` | Claim rewards from unknown contract | Unknown selector and opaque parameters | `UNKNOWN_CONTRACT` | Teaches "unknown is not safe" |

## Extended Research Corpus

The full airdrop-safety research set should be larger than the core demo. Use
these adjacent fixtures to test negative controls, direct outflow, existing
allowance reuse, migration-style bundles, and address-poisoning variants.

| Case | Fixture | Why it belongs in the broader airdrop-safety corpus |
| --- | --- | --- |
| `00-01` | `erc20-unlimited-approval-phishing` | Core fake claim -> unlimited approval |
| `00-02` | `erc20-large-approval-fake-swap` | Fake migration/swap page requests a very large approval; useful for non-unlimited but excessive allowance rules |
| `00-03` | `eip2612-permit-unlimited-drainer` | Core gasless claim -> Permit authorization |
| `00-04` | `nft-setapprovalforall-fake-airdrop` | Core NFT airdrop verify -> collection-wide operator permission |
| `00-05` | `nft-setapprovalforall-revoke-benign` | Benign revoke control so the system does not flag `setApprovalForAll(false)` as a drainer |
| `00-06` | `token-transfer-to-drainer` | Fake support/refund style page causing direct token outflow |
| `00-08` | `transferfrom-prior-allowance-drain` | Fake allowance check that reuses existing approval to drain assets |
| `00-09` | `multicall-hidden-approval-and-transfer` | Core bundle with hidden approval and transfer payloads |
| `00-10` | `multicall-deadline-fake-migration` | Deadline-based migration bundle with hidden approval and transfer behavior |
| `00-11` | `universal-router-execute-permit2-style-drain` | Core router / Permit2-style bundle |
| `00-12` | `unknown-claim-rewards-selector` | Core unknown claim selector |
| `00-14` | `native-address-poisoning-lookalike` | Adjacent wallet-safety case: poisoned recipient looks familiar |
| `00-15` | `native-transfer-to-synthetic-drainer` | Adjacent native-asset outflow to a fixture drainer |

Cases `00-07`, `00-13`, and `00-16` through `00-22` are still useful for the
overall TxRiskAgent corpus, but they are less central to the airdrop claim
storyline. Keep them for broader token-risk, protocol-risk, burn-address, and
unknown-contract coverage rather than the first airdrop demo.

## 00-01 Fake Claim -> Unlimited ERC20 Approval

- Fixture: `dump-tx/2026-06-03T00-01-00-000Z-erc20-unlimited-approval-phishing.json`
- Existing report: `output/risk-reports/2026-06-03T00-01-00-000Z-erc20-unlimited-approval-phishing.risk.json`
- Origin: `https://claim-rewards.invalid`
- Decoded function: `approve(address,uint256)`
- Current verdict: `CRITICAL`, recommended action `REJECT`

User thinks:

- They are claiming token rewards from an airdrop page.

Actually happens:

- The transaction calls `approve(spender, uint256.max)` on synthetic
  `LAB-USDC`.
- The spender is `0x3000000000000000000000000000000000000001`.
- The allowance is effectively unlimited.

Asset impact:

- The spender can later use `transferFrom` to move the approved token without
  another approval prompt.

Risk judgment:

- Critical. This is an intent mismatch: the page framing is "claim", but the
  transaction grants spending permission.

User warning copy:

> This is not a normal airdrop claim. It gives another address unlimited
> permission to spend your LAB-USDC. Reject the signature unless you can
> independently verify the spender and exact allowance.

## 00-03 Gasless Claim -> EIP-2612 Permit Approval

- Fixture: `dump-tx/2026-06-03T00-03-00-000Z-eip2612-permit-unlimited-drainer.json`
- Existing report: `output/risk-reports/2026-06-03T00-03-00-000Z-eip2612-permit-unlimited-drainer.risk.json`
- Origin: `https://gasless-claim.invalid`
- Decoded function: `permit(address,address,uint256,uint256,uint8,bytes32,bytes32)`
- Current verdict: `CRITICAL`, recommended action `REJECT`

User thinks:

- They are signing a gasless claim, login, or eligibility confirmation.

Actually happens:

- The calldata represents an EIP-2612 `permit` approval.
- The spender receives permission to spend synthetic `LAB-DAI`.
- The approval value is effectively unlimited.

Asset impact:

- A Permit signature can grant token spending rights without a separate
  on-chain `approve` transaction first.
- The user may see a gasless flow and underestimate the asset impact.

Risk judgment:

- Critical. "Gasless" only means the user may not pay gas for the approval
  transaction; it does not mean no asset permission is granted.

User warning copy:

> This is not a harmless gasless claim. It is a Permit authorization that can
> let the spender move your LAB-DAI. Reject it if the page promised a claim,
> login, or wallet verification.

## 00-04 NFT Airdrop Verify -> setApprovalForAll

- Fixture: `dump-tx/2026-06-03T00-04-00-000Z-nft-setapprovalforall-fake-airdrop.json`
- Existing report: `output/risk-reports/2026-06-03T00-04-00-000Z-nft-setapprovalforall-fake-airdrop.risk.json`
- Origin: NFT airdrop / verification scenario from `description.txt`
- Decoded function: `setApprovalForAll(address,bool)`
- Current verdict: `CRITICAL`, recommended action `REJECT`

User thinks:

- They are verifying a wallet or claiming an NFT airdrop.

Actually happens:

- The transaction calls `setApprovalForAll(operator, true)` on a synthetic NFT
  collection.
- The operator is a fixture drainer address.

Asset impact:

- The operator can transfer every NFT in the collection for that wallet.

Risk judgment:

- Critical. A legitimate NFT claim should not require collection-wide transfer
  permission to an unknown operator.

User warning copy:

> This request gives another address control over all NFTs in this collection.
> Reject it unless you deliberately intend to grant marketplace-style operator
> permissions.

## 00-09 Claim Bundle -> Multicall Hidden Approval and Transfer

- Fixture: `dump-tx/2026-06-03T00-09-00-000Z-multicall-hidden-approval-and-transfer.json`
- Existing report: `output/risk-reports/2026-06-03T00-09-00-000Z-multicall-hidden-approval-and-transfer.risk.json`
- Origin: `https://bundle-claim.invalid`
- Decoded function: `multicall(bytes[])`
- Current verdict: `CRITICAL`, recommended action `REJECT`

User thinks:

- They are running a single bundled claim operation.

Actually happens:

- The outer selector is `multicall(bytes[])`.
- The fixture calldata embeds an `approve(uint256.max)` payload and a
  `transfer` payload.
- The current deterministic analyzer flags the bundle as a critical risk but
  records low confidence because recursive decoding is not fully implemented.

Asset impact:

- Bundles can hide multiple asset or permission changes behind one wallet
  confirmation.

Risk judgment:

- Critical for the demo. Product wording should emphasize uncertainty: if the
  analyzer cannot expand every child call, the missing evidence is not safety.

User warning copy:

> This claim is wrapped in a multicall. It may contain more than one action,
> including approvals or transfers. Reject it unless the internal calls are
> fully decoded and match the expected claim.

## 00-11 Router / Permit2-Style Claim -> Universal Router Execute

- Fixture: `dump-tx/2026-06-03T00-11-00-000Z-universal-router-execute-permit2-style-drain.json`
- Existing report: `output/risk-reports/2026-06-03T00-11-00-000Z-universal-router-execute-permit2-style-drain.risk.json`
- Decoded function: `execute(bytes,bytes[],uint256)`
- Current verdict: `CRITICAL`, recommended action `REJECT`

User thinks:

- They are claiming through a router, rewards portal, migration helper, or
  Permit2-style flow.

Actually happens:

- The transaction enters a Universal Router-style `execute` path.
- The bundle can combine authorization, routing, transfer, and deadline logic.
- The current analyzer treats it as `MULTICALL` and requires recursive decode
  or external simulation for full confidence.

Asset impact:

- Router-style flows compress several steps into one signing surface. A user may
  only see the wrapper while the dangerous action is nested.

Risk judgment:

- Critical in this fixture because the route target is a known local risk
  sample and the inner actions are not fully transparent.

User warning copy:

> This is a router-style bundled action, not a plain claim. It can hide Permit2
> or transfer steps behind one confirmation. Reject it until every internal
> action is decoded.

## 00-12 Unknown Claim Rewards Selector

- Fixture: `dump-tx/2026-06-03T00-12-00-000Z-unknown-claim-rewards-selector.json`
- Existing report: `output/risk-reports/2026-06-03T00-12-00-000Z-unknown-claim-rewards-selector.risk.json`
- Decoded selector: `0x4e71d92d`
- Current verdict: `MEDIUM`, recommended action `CONTINUE_WITH_CAUTION`

User thinks:

- They are claiming rewards from an airdrop page.

Actually happens:

- The analyzer cannot resolve the selector or explain the parameters from the
  local selector set.
- No live simulation, source verification, or threat intelligence was run in the
  baseline output.

Asset impact:

- Unknown from deterministic facts alone.

Risk judgment:

- Medium in the current generic analyzer. For an airdrop-specific UX, this
  should be framed as "opaque claim risk" rather than "probably safe".

User warning copy:

> SignShield cannot explain what this claim call will do. Do not treat unknown
> calldata as safe. Verify the official link, contract source, and simulation
> result before signing.

## Airdrop-Specific Risk Rules

For airdrop flows, prioritize these checks:

1. If the page says `claim`, `airdrop`, `rewards`, `gasless`, or `verify`, but
   the decoded intent is `ERC20_APPROVAL`, `NFT_APPROVAL`, `TOKEN_TRANSFER`, or
   `MULTICALL`, mark an intent mismatch.
2. If approval amount is unlimited or collection-wide, recommend reject.
3. If the action is Permit or Permit2-style, state that gasless signing can
   still grant spending rights.
4. If a bundle cannot be recursively decoded, surface uncertainty as a risk
   factor, not as an absence of risk.
5. If the selector is unknown and the origin looks like a claim page, use
   "opaque claim risk" language and request simulation/source verification.

## Demo Selection

For a short hackathon demo, use three cases:

1. `00-01`: fake claim becomes unlimited ERC20 approval.
2. `00-03`: gasless claim becomes Permit approval.
3. `00-04`: NFT verify becomes collection-wide operator approval.

If there is time, add `00-09` or `00-11` to show why recursive bundle analysis
is the next technical milestone.
