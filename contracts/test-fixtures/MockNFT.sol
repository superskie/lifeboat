// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IERC721Receiver {
    function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4);
}

/// Test-only ERC-721 with receiver checks on safe transfers and safe mints.
contract MockNFT {
    uint256 public nextId = 1;
    mapping(uint256 => address) public ownerOf;
    mapping(address => uint256) public balanceOf;
    mapping(uint256 => address) public getApproved;
    mapping(address => mapping(address => bool)) public isApprovedForAll;

    event Transfer(address indexed from, address indexed to, uint256 indexed id);

    function safeMint(address to) public returns (uint256 id) {
        id = nextId++;
        ownerOf[id] = to;
        balanceOf[to] += 1;
        emit Transfer(address(0), to, id);
        _check(address(0), to, id);
    }

    function approve(address spender, uint256 id) external {
        require(msg.sender == ownerOf[id], "owner");
        getApproved[id] = spender;
    }

    function setApprovalForAll(address operator, bool approved) external {
        isApprovedForAll[msg.sender][operator] = approved;
    }

    function transferFrom(address from, address to, uint256 id) public {
        require(ownerOf[id] == from, "from");
        require(msg.sender == from || getApproved[id] == msg.sender || isApprovedForAll[from][msg.sender], "auth");
        ownerOf[id] = to;
        balanceOf[from] -= 1;
        balanceOf[to] += 1;
        delete getApproved[id];
        emit Transfer(from, to, id);
    }

    function safeTransferFrom(address from, address to, uint256 id) external {
        transferFrom(from, to, id);
        _check(from, to, id);
    }

    function safeTransferFrom(address from, address to, uint256 id, bytes calldata) external {
        transferFrom(from, to, id);
        _check(from, to, id);
    }

    function _check(address from, address to, uint256 id) internal {
        if (to.code.length == 0) return;
        require(IERC721Receiver(to).onERC721Received(msg.sender, from, id, "") == 0x150b7a02, "receiver");
    }
}
