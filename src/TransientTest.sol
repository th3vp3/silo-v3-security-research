// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @dev Minimal reproduction: can delegatecall clear caller's transient storage?
contract VaultMock {
    bool transient _lock;
    uint256 public reentryCount;

    function doWork(address logic) external {
        require(!_lock, "locked");
        _lock = true;

        // Simulate _claimRewards() using delegatecall
        (bool success,) = logic.delegatecall(
            abi.encodeWithSignature("execute()")
        );
        require(success, "delegatecall failed");

        _lock = false;
    }

    function deposit() external {
        require(!_lock, "locked-on-deposit");
        reentryCount++;
    }

    function isLocked() external view returns (bool) {
        return _lock;
    }
}

contract MaliciousLogic {
    // When executed via delegatecall, this runs in VaultMock's context
    // including its transient storage

    function execute() external {
        // Try to clear the transient lock
        // In delegatecall context, tstore writes to CALLER's transient storage
        assembly {
            tstore(0, 0)  // slot 0 = _lock (first transient var)
        }

        // Now try to re-enter deposit()
        // In delegatecall context, address(this) == VaultMock
        // So we call ourselves (VaultMock.deposit)
        (bool success,) = address(this).call(
            abi.encodeWithSignature("deposit()")
        );
        // Note: success may be false if lock is still active
        // We just want to test if tstore cleared it
    }
}

contract BenignLogic {
    function execute() external {
        // Does nothing - control test
    }
}
