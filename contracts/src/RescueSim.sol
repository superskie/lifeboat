// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {RescueCore} from "./RescueCore.sol";

/// @notice Never deployed. Used only as eth_call override code at the victim address to report the
/// result of every call and the balances afterwards, without stopping at the first failure.
contract RescueSim is RescueCore {
    struct Call {
        address to;
        uint256 value;
        bytes data;
    }

    struct Probe {
        address target;
        bytes data;
    }

    function simulate(Call[] calldata calls, Probe[] calldata probes)
        external
        payable
        returns (bool[] memory ok, bytes[] memory ret, bytes[] memory probeRet, uint256 nativeAfter)
    {
        ok = new bool[](calls.length);
        ret = new bytes[](calls.length);
        for (uint256 i = 0; i < calls.length; ++i) {
            (ok[i], ret[i]) = calls[i].to.call{value: calls[i].value}(calls[i].data);
        }
        probeRet = new bytes[](probes.length);
        for (uint256 i = 0; i < probes.length; ++i) {
            if (probes[i].data.length == 0) {
                // A probe without calldata reads the native balance.
                probeRet[i] = abi.encode(probes[i].target.balance);
                continue;
            }
            (bool success, bytes memory out) = probes[i].target.staticcall(probes[i].data);
            probeRet[i] = success ? out : bytes("");
        }
        nativeAfter = address(this).balance;
    }
}
