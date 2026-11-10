// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IERC1155Receiver {
    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external returns (bytes4);
}

/// Test-only ERC-1155 with the single-transfer receiver check.
contract MockMulti {
    mapping(uint256 => mapping(address => uint256)) internal _bal;

    function balanceOf(address account, uint256 id) external view returns (uint256) {
        return _bal[id][account];
    }

    function mint(address to, uint256 id, uint256 amount) external {
        _bal[id][to] += amount;
        _check(address(0), to, id, amount);
    }

    function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes calldata) external {
        require(msg.sender == from, "auth");
        require(_bal[id][from] >= amount, "balance");
        _bal[id][from] -= amount;
        _bal[id][to] += amount;
        _check(from, to, id, amount);
    }

    function _check(address from, address to, uint256 id, uint256 amount) internal {
        if (to.code.length == 0) return;
        require(IERC1155Receiver(to).onERC1155Received(msg.sender, from, id, amount, "") == 0xf23a6e61, "receiver");
    }
}
