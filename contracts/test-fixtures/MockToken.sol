// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// Test-only ERC-20. A non-zero fee sends that share of every transfer to feeSink.
contract MockToken {
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;
    uint256 public totalSupply;
    uint256 public feeBps;
    address public feeSink;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(string memory name_, string memory symbol_) {
        name = name_;
        symbol = symbol_;
    }

    function setFee(uint256 bps, address sink) external {
        feeBps = bps;
        feeSink = sink;
    }

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _move(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "allowance");
        if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;
        _move(from, to, amount);
        return true;
    }

    function _move(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        uint256 fee = amount * feeBps / 10_000;
        if (fee > 0) {
            balanceOf[feeSink] += fee;
            emit Transfer(from, feeSink, fee);
        }
        balanceOf[to] += amount - fee;
        emit Transfer(from, to, amount - fee);
    }
}
