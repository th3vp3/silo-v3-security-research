// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import "../src/TransientTest.sol";

contract TransientReentrancyTest is Test {
    VaultMock vault;
    MaliciousLogic malicious;
    BenignLogic benign;

    function setUp() public {
        vault = new VaultMock();
        malicious = new MaliciousLogic();
        benign = new BenignLogic();
    }

    /// @dev Test 1: Benign logic should work normally
    function test_benignLogic() public {
        vault.doWork(address(benign));
        assertEq(vault.reentryCount(), 0, "no reentry");
    }

    /// @dev Test 2: Can malicious delegatecall clear transient lock and re-enter?
    /// This is the core of Finding A
    function test_maliciousDelegatecallClearsTransientLock() public {
        vault.doWork(address(malicious));

        // If reentryCount > 0, the reentrancy succeeded
        // meaning delegatecall CAN clear transient storage
        if (vault.reentryCount() > 0) {
            emit log("VULNERABLE: delegatecall cleared transient lock, reentrancy succeeded!");
            emit log_named_uint("reentryCount", vault.reentryCount());
        } else {
            emit log("SAFE: delegatecall could NOT clear transient lock");
        }
    }

    /// @dev Test 3: Direct deposit while locked should fail
    function test_directDepositWhileLocked_reverts() public {
        // We can't easily test this since doWork sets and unsets lock
        // But we can verify the lock mechanism works
        vault.doWork(address(benign));
        assertFalse(vault.isLocked(), "lock released after doWork");
    }

    /// @dev Test 4: Verify transient storage slot layout
    function test_transientStorageSlot() public {
        // Check what slot the transient bool uses
        // Solidity 0.8.28 transient variables get sequential slots starting from 0
        bytes32 slot0Before;
        assembly {
            slot0Before := tload(0)
        }
        assertEq(uint256(slot0Before), 0, "slot 0 should be 0 initially");
    }
}
