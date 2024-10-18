// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/SignatureVerifier.sol";

contract MockERC20 is IERC20 {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract SignatureVerificationTest is Test {
    SignatureVerification public signatureVerification;
    MockERC20 public token;
    uint256 public constant CLAIM_AMOUNT = 100 * 1e18;

    address public sam = address(0x1);
    uint256 public samPrivateKey = 0xa11ce;

    function setUp() public {
        token = new MockERC20();
        address[] memory whitelist = new address[](1);
        whitelist[0] = sam;
        signatureVerification = new SignatureVerification(whitelist, address(token));
        token.mint(address(signatureVerification), CLAIM_AMOUNT * 10); 
        vm.deal(sam, 1 ether); 
    }

    function testClaimTokens() public {
        bytes32 messageHash = keccak256(abi.encodePacked(sam));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(samPrivateKey, ethSignedMessageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(sam);
        signatureVerification.claimTokens(messageHash, signature);

        assertEq(token.balanceOf(sam), CLAIM_AMOUNT, "Incorrect amount claimed");
    }

    function testCannotClaimTwice() public {
        bytes32 messageHash = keccak256(abi.encodePacked(sam));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(samPrivateKey, ethSignedMessageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.startPrank(sam);
        signatureVerification.claimTokens(messageHash, signature);
        
        vm.expectRevert("Already claimed");
        signatureVerification.claimTokens(messageHash, signature);
        vm.stopPrank();
    }

    function testCannotClaimIfNotWhitelisted() public {
        address bob = address(0x2);
        uint256 bobPrivateKey = 0xb0b;

        bytes32 messageHash = keccak256(abi.encodePacked(bob));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(bobPrivateKey, ethSignedMessageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(bob);
        vm.expectRevert("Address not whitelisted");
        signatureVerification.claimTokens(messageHash, signature);
    }

    function testCannotClaimWithInvalidSignature() public {
        bytes32 messageHash = keccak256(abi.encodePacked(sam));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xbad, ethSignedMessageHash); // Wrong private key
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(sam);
        vm.expectRevert("Invalid signature");
        signatureVerification.claimTokens(messageHash, signature);
    }
}