// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

//  import for Openzepplin MerkleProof contract. This will allow us to use
//  the 'MerkleProof.verify' method

contract Merkle {
    bytes32 public merkleRoot = 0x66a01cf30f7b10c8e231f747ce537cdecce6d334aa15f177e75f0121a12a22f9;

    mapping(address => bool) public whitelistClaimed;

    function whitelistMint(bytes32[] calldata _merkeProof) public {
        require(!whitelistClaimed[msg.sender], "Address has already claimed.");
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender));
        require(verify(_merkeProof, merkleRoot, leaf), "Invalid proof.");

        whitelistClaimed[msg.sender] = true;

        // mint the reserved token here
    }

    //  Test
    //  0x55dd582ca492be9745af91d859b4789f0abd08b2
    //  ["0xe8776ae76018115d0488fa709ef9b6a9be18ab31329d2b3624088a27a8c987cb","0xfb9ce283b08ba30191d838aff3625db704482d4252e1681f634eae13579eb6d6","0x4c01b3b02a461775426dfda6db330aad0f0623fa013913ad8d86bca93d6b4bac","0xf162da81de20cc44cb85b199773768f58d28ed5682f802241ae425d2e385de1d","0x8f7d84ad55aae2f62da924a22d890c2d595d7e4fd70824ce02dc969d292eb92a","0x38611783e9fa36e5b789d01dc731f395c60aa793434fa76a34e0284bdcebc6cb","0xa0ffa934615e8e0f5c68348b53424d0cfe873ec0c7cffdb8fa6d518d384ff445","0xff402ba8223a2c7ff714df043559b62f660948c976fb06b21bd290dad64b38b0","0x5fc53bdd85970fd9b4572e6f57c1550565f4a5eb855a58ed89dca2c22da5e848","0x53c544df22ed411d9daf541f21a56614636210ed6063a07dfe51c30ddd1539eb","0xe2d2171e343572ef44f3e85e629fe927435e18eca49ebffed24e476803a496bb","0x9fafedccd753138cf175d47f9071c419e3948cc3cbb5ca196245b8eeb2f0f0da"]
    function TestWhitelist(address _to, bytes32[] calldata _merkeProof) public {
        require(!whitelistClaimed[_to], "Address has already claimed.");
        bytes32 leaf = keccak256(abi.encodePacked(_to));
        require(verify(_merkeProof, merkleRoot, leaf), "Invalid proof.");

        whitelistClaimed[_to] = true;

        // mint the reserved token here
    }


    //  ============================================
     /**
     * @dev Returns true if a `leaf` can be proved to be a part of a Merkle tree
     * defined by `root`. For this, a `proof` must be provided, containing
     * sibling hashes on the branch from the leaf to the root of the tree. Each
     * pair of leaves and each pair of pre-images are assumed to be sorted.
     */
    function verify(
        bytes32[] memory proof,
        bytes32 root,
        bytes32 leaf
    ) internal pure returns (bool) {
        return processProof(proof, leaf) == root;
    }

    /**
     * @dev Returns the rebuilt hash obtained by traversing a Merkle tree up
     * from `leaf` using `proof`. A `proof` is valid if and only if the rebuilt
     * hash matches the root of the tree. When processing the proof, the pairs
     * of leafs & pre-images are assumed to be sorted.
     *
     * _Available since v4.4._
     */
    function processProof(bytes32[] memory proof, bytes32 leaf) internal pure returns (bytes32) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            if (computedHash <= proofElement) {
                // Hash(current computed hash + current element of the proof)
                computedHash = _efficientHash(computedHash, proofElement);
            } else {
                // Hash(current element of the proof + current computed hash)
                computedHash = _efficientHash(proofElement, computedHash);
            }
        }
        return computedHash;
    }

    function _efficientHash(bytes32 a, bytes32 b) private pure returns (bytes32 value) {
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
    }
}
