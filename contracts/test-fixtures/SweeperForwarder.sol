// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// Test-only stand-in for a delegation a sweeper set up itself: forwards any ETH that arrives.
contract SweeperForwarder {
    address payable public immutable sink;

    constructor(address payable sink_) {
        sink = sink_;
    }

    receive() external payable {
        (bool ok, ) = sink.call{value: msg.value}("");
        require(ok, "forward");
    }
}
