// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice Shared by RescueBatch and RescueSim so the simulated victim behaves like the delegated one.
/// Helpers move the balance that exists at execution time. They only accept calls from the
/// account itself: from inside a batch, or from the leaked key, which can move the funds anyway.
abstract contract RescueCore {
    function sweepERC20(address token, address to) external {
        require(msg.sender == address(this), "self only");
        (bool ok, bytes memory ret) = token.staticcall(abi.encodeWithSelector(0x70a08231, address(this)));
        require(ok && ret.length >= 32, "balanceOf failed");
        uint256 bal = abi.decode(ret, (uint256));
        if (bal == 0) return;
        (ok, ret) = token.call(abi.encodeWithSelector(0xa9059cbb, to, bal));
        require(ok && (ret.length == 0 || abi.decode(ret, (bool))), "transfer failed");
    }

    function sweepNative(address payable to) external {
        require(msg.sender == address(this), "self only");
        uint256 bal = address(this).balance;
        if (bal == 0) return;
        (bool ok, ) = to.call{value: bal}("");
        require(ok, "native send failed");
    }

    /// Once delegated, the account has code, so safe transfers and safe mints to it call these.
    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return 0x150b7a02;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        return 0xf23a6e61;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return 0xbc197c81;
    }

    function supportsInterface(bytes4 id) external pure returns (bool) {
        return id == 0x01ffc9a7 || id == 0x150b7a02 || id == 0x4e2312e0;
    }

    receive() external payable {}
}
