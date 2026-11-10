// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {RescueCore} from "./RescueCore.sol";

/// @notice EIP-7702 delegate for a drained EOA. Only the operator can make the account run a batch.
/// The operator is immutable, so the check lives in code and survives delegation (storage would be
/// the victim's).
contract RescueBatch is RescueCore {
    struct Call {
        address to;
        uint256 value;
        bytes data;
    }

    /// What must be true at the safe address once the calls have run. A dry run can be told apart
    /// from the real transaction by a hostile call target, so the promised outcome is enforced here.
    /// kind 0: the number read from `target` with `data` must grow by at least `min`.
    /// kind 1: the word read from `target` with `data` must equal `min` afterwards (an NFT owner).
    /// kind 2: the native balance of `target` must grow by at least `min`.
    struct Check {
        address target;
        bytes data;
        uint256 min;
        uint8 kind;
    }

    address public immutable operator;

    constructor(address operator_) {
        operator = operator_;
    }

    function execute(Call[] calldata calls, Check[] calldata checks) external payable {
        require(msg.sender == operator, "not operator");
        uint256[] memory start = new uint256[](checks.length);
        for (uint256 i = 0; i < checks.length; ++i) {
            start[i] = _read(checks[i]);
        }
        for (uint256 i = 0; i < calls.length; ++i) {
            (bool ok, bytes memory ret) = calls[i].to.call{value: calls[i].value}(calls[i].data);
            if (!ok) {
                assembly ("memory-safe") {
                    revert(add(ret, 32), mload(ret))
                }
            }
        }
        for (uint256 i = 0; i < checks.length; ++i) {
            uint256 end = _read(checks[i]);
            if (checks[i].kind == 1) {
                require(end == checks[i].min, "the safe address did not receive an approved asset");
            } else {
                require(
                    end >= start[i] && end - start[i] >= checks[i].min,
                    "the safe address would receive less than approved"
                );
            }
        }
    }

    function _read(Check calldata check) private view returns (uint256 value) {
        if (check.kind == 2) return check.target.balance;
        (bool ok, bytes memory ret) = check.target.staticcall(check.data);
        if (ok && ret.length >= 32) {
            assembly ("memory-safe") {
                value := mload(add(ret, 32))
            }
        }
    }
}
