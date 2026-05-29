# Silo Protocol V3 — Transient Storage Reentrancy Vulnerability

Security research and proof-of-concept for a reentrancy vulnerability discovered in Silo Finance V3's `SiloVault` contract, submitted to Immunefi bug bounty program.

## Vulnerability Summary

| Field | Detail |
|-------|--------|
| **Protocol** | Silo Finance V3 (Sonic Chain) |
| **Contract** | `SiloVault.sol` |
| **Type** | Reentrancy Guard Bypass via EIP-1153 Transient Storage |
| **Root Cause** | `_claimRewards()` uses `delegatecall` to execute claiming logic; per EIP-1153, delegatecall operates on the caller's transient storage, allowing executed code to clear the `bool transient _lock` reentrancy guard with `tstore(0, 0)` |
| **Impact** | Reentrancy into `deposit()` with stale `lastTotalAssets`, enabling share price manipulation and vault fund theft |
| **Severity** | Medium (Immunefi) / High (Researcher) |
| **TVL at Risk** | ~779,751 wS (Sonic Chain) |

## Attack Flow

```
SiloVault.deposit()
  └── _lock = true (tstore)
  └── _accrueFee()
  └── _claimRewards() ── delegatecall ──► Malicious Claiming Logic
                                              └── tstore(0, 0)  // clear _lock
                                              └── re-enter deposit() with stale share price
  └── mint shares at undervalued price
```

## PoC Test Results

All 4 proof-of-concept tests pass on Sonic mainnet fork:

| Test | Description |
|------|-------------|
| `SiloVaultPoC_Report.t.sol` | Full PoC — reentrancy attack validation |
| `RealSiloVaultAnalysis.t.sol` | Real SiloVault flow analysis |
| `RealSiloVaultFeeExploit.t.sol` | Fee exploitation analysis |
| `TransientStorageProof.t.sol` | Transient storage behavior proof |

## Repository Structure

```
├── src/SiloVaultPoC.sol          # PoC exploit contract
├── test/                          # Foundry test suite
├── silo-contracts-v3/             # Silo V3 reference implementation
└── foundry.toml                   # Foundry config (EVM: cancun)
```

## Suggested Fixes

1. **Minimal**: Verify `_lock` state after each `delegatecall`
2. **Stronger**: Replace `delegatecall` with regular `call`
3. **Defense-in-depth**: Add storage-based reentrancy guard alongside transient guard

## Tech Stack

- Solidity `^0.8.28` + EVM Cancun (EIP-1153)
- Foundry build & test framework
- OpenZeppelin v5, Chainlink, Uniswap V3, Morpho Blue

## License

Research material — see individual files for applicable licenses.
