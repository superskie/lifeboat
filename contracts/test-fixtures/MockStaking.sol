// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IStakeToken {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

interface IReceiptNFT {
    function safeMint(address) external returns (uint256);
}

/// Test-only staking pool. withdraw() returns the stake; claimReward() safe-mints a receipt NFT.
contract MockStaking {
    IStakeToken public immutable token;
    IReceiptNFT public immutable receipt;
    mapping(address => uint256) public staked;

    constructor(IStakeToken token_, IReceiptNFT receipt_) {
        token = token_;
        receipt = receipt_;
    }

    function stake(uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount), "pull");
        staked[msg.sender] += amount;
    }

    function withdraw() external {
        uint256 amount = staked[msg.sender];
        require(amount > 0, "nothing staked");
        staked[msg.sender] = 0;
        require(token.transfer(msg.sender, amount), "push");
    }

    /// Many pools report the position this way, which makes the pool look like a token to a watcher.
    function balanceOf(address account) external view returns (uint256) {
        return staked[account];
    }

    function claimReward() external returns (uint256) {
        require(staked[msg.sender] > 0, "nothing staked");
        return receipt.safeMint(msg.sender);
    }
}
