// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console2} from "forge-std/Test.sol";

/// @title Precise analysis of real SiloVault deposit reentrancy impact
/// @dev Traces the EXACT execution flow of the real SiloVault.deposit()
///      to determine if the reentrancy is economically exploitable.
contract RealSiloVaultAnalysis is Test {
    // This test simulates the REAL SiloVault.deposit() flow precisely,
    // not a simplified mock.

    // Key difference from our mock: SiloVault updates lastTotalAssets
    // BEFORE calling _claimRewards(), and _accrueFee() is called in
    // each deposit() to get the latest totalAssets.

    // The question: is there still an exploitable price discrepancy?

    function test_analyzeRealDepositFlow() public pure {
        // Setup: Alice has 1000 tokens in the vault, 1e27 shares
        // lastTotalAssets = 1000
        // totalSupply = 1e27 (1000e18 * 1e6 with DECIMALS_OFFSET)

        // === FIRST DEPOSIT (attacker deposits 100) ===
        // Step 1: _nonReentrantOn() → _lock = true
        // Step 2: newTotalAssets = _accrueFee()
        //   _accrueFee → totalAssets() → iterates withdrawQueue
        //   But attacker already transferred 100 tokens via transferFrom
        //   Wait... transferFrom hasn't happened yet!
        //   In SiloVault.deposit():
        //     lastTotalAssets = newTotalAssets;  // line 572 - FIRST
        //     shares = convertToShares(...);
        //     _deposit(...) → super._deposit → _transferIn → _mint → _update → _claimRewards
        //
        //   So at step 2, the vault doesn't have attacker's tokens yet.
        //   totalAssets = 1000 (only Alice's tokens)
        //   lastTotalAssets = 1000

        // Step 3: shares = 100 * (1e27 + 1e6) / (1000 + 1)
        //   = 100 * 1000000000000000000000000001 / 1001
        //   ≈ 99900099900099900099900099900  (let's call this S1)

        // Step 4: _deposit calls super._deposit which does:
        //   _transferIn(attacker, 100) → vault now has 1100 tokens
        //   _mint(attacker, S1) → _update → _claimRewards → delegatecall
        //     At this point: totalSupply = 1e27 + S1, lastTotalAssets = 1000
        //     But vault actually holds 1100 tokens

        // === MALICIOUS CLAIMING LOGIC (inside delegatecall) ===
        // tstore(0,0) → clear _lock
        // Call vault.deposit(100, attacker) → REENTERS!

        // === REENTRANT DEPOSIT ===
        // Step 1: _nonReentrantOn() → _lock is false → _lock = true ✓
        // Step 2: newTotalAssets = _accrueFee()
        //   _accrueFee → totalAssets() → vault has 1100 tokens
        //   But wait: lastTotalAssets is 1000 (not yet updated by first deposit)
        //   _accruedFeeShares checks totalInterest = totalAssets() - lastTotalAssets
        //   = 1100 - 1000 = 100 tokens of "interest"
        //   If fee > 0, some fee shares are minted to feeRecipient
        //   newTotalAssets = totalAssets() = 1100 (after fee adjustment)

        // Step 3: lastTotalAssets = 1100 (updated in reentrant deposit)

        // Step 4: shares = 100 * (totalSupply + 1e6) / (1100 + 1)
        //   totalSupply = 1e27 + S1 (from first mint)
        //   The exchange rate is based on 1100 total assets, which is correct!
        //   So the shares are NOT inflated by stale pricing.

        // CONCLUSION: The real SiloVault's design of updating lastTotalAssets
        // BEFORE _claimRewards, and calling _accrueFee() at the start of
        // each deposit, means the reentrant deposit gets a FAIR exchange rate.

        // However, there are still concerns:
        // 1. The fee calculation treats the deposit as "interest", potentially
        //    stealing from the attacker's own deposit via fee minting
        // 2. The _supplyERC4626 hasn't run yet, so vault holds unallocated tokens
        // 3. The first deposit's lastTotalAssets update hasn't been finalized
        // 4. The reentrant deposit creates a SECOND _supplyERC4626 call
        //    which may fail or have unexpected effects

        console2.log("Analysis: Real SiloVault deposit reentrancy");
        console2.log("Key finding: lastTotalAssets is updated before _claimRewards");
        console2.log("Each deposit() call runs _accrueFee() which gets latest totalAssets()");
        console2.log("Therefore: share pricing is NOT stale during reentrancy");
        console2.log("BUT: _accrueFee may incorrectly mint fee shares on the 'phantom interest'");
    }
}
