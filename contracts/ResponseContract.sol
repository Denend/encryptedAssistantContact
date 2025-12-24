// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;

import { FHE, euint8, externalEuint8 } from "@fhevm/solidity/lib/FHE.sol";
import { ZamaEthereumConfig } from "@fhevm/solidity/config/ZamaConfig.sol";

/// @title FHE-encrypted response storage
/// @notice Stores a response as encrypted UTF-8 bytes using FHEVM
contract FHEResponseContract is ZamaEthereumConfig {
    uint16 public constant MAX_LEN = 2048;

    euint8[MAX_LEN] private _response;
    uint16 private _length;

    event ResponseUpdated(address indexed sender, uint16 length);

    /// @param encryptedChars array of encrypted uint8 (UTF-8 bytes)
    /// @param length actual response length (bytes)
    /// @param inputProof ZK proof binding ciphertexts to sender + contract
    function setResponse(
        bytes32[] calldata encryptedChars,
        uint16 length,
        bytes calldata inputProof
    ) external {
        require(length <= MAX_LEN, "Response too long");
        require(encryptedChars.length >= length, "Invalid ciphertext array");

        _length = length;

        for (uint16 i = 0; i < length; i++) {
            externalEuint8 ext = externalEuint8.wrap(encryptedChars[i]);
            euint8 ch = FHE.fromExternal(ext, inputProof);

            _response[i] = ch;

            // allow contract + caller to decrypt off-chain
            FHE.allowThis(ch);
            FHE.allow(ch, msg.sender);
        }

        emit ResponseUpdated(msg.sender, length);
    }

    /// @notice Read encrypted byte at index
    function getEncryptedChar(uint16 i) external view returns (euint8) {
        require(i < _length, "Out of bounds");
        return _response[i];
    }

    function length() external view returns (uint16) {
        return _length;
    }
}