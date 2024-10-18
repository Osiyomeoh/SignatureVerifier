// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract SignatureVerification {
    IERC20 public token;
    mapping(address => bool) public whitelist;
    mapping(address => bool) public hasClaimed;

    constructor(address[] memory _whitelist, address tokenAddress) {
        token = IERC20(tokenAddress);
        for (uint256 i = 0; i < _whitelist.length; i++) {
            whitelist[_whitelist[i]] = true;
        }
    }

    function claimTokens(bytes32 messageHash, bytes memory signature) external {
        require(whitelist[msg.sender], "Address not whitelisted");
        require(!hasClaimed[msg.sender], "Already claimed");
        address signer = recoverSigner(messageHash, signature);
        require(signer == msg.sender, "Invalid signature");
        hasClaimed[msg.sender] = true;
        require(token.transfer(msg.sender, 100 * 10**18), "Token transfer failed");
    }

    function recoverSigner(bytes32 messageHash, bytes memory signature) internal pure returns (address) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        require(v == 27 || v == 28, "Invalid signature 'v' value");

        return ecrecover(toEthSignedMessageHash(messageHash), v, r, s);
    }

    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
}