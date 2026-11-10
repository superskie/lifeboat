// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IVestToken {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

/// Test-only cliff vesting: everything it holds goes to the beneficiary at unlockTime.
contract MockVesting {
    IVestToken public immutable token;
    address public immutable beneficiary;
    uint256 public immutable unlockTime;

    constructor(IVestToken token_, address beneficiary_, uint256 unlockTime_) {
        token = token_;
        beneficiary = beneficiary_;
        unlockTime = unlockTime_;
    }

    function claim() external {
        require(msg.sender == beneficiary, "not beneficiary");
        require(block.timestamp >= unlockTime, "locked");
        uint256 amount = token.balanceOf(address(this));
        require(amount > 0, "nothing to claim");
        require(token.transfer(beneficiary, amount), "push");
    }
}
