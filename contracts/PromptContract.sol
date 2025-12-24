// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;

import { FHE, euint8, externalEuint8 } from "@fhevm/solidity/lib/FHE.sol";
import { ZamaEthereumConfig } from "@fhevm/solidity/config/ZamaConfig.sol";

/// @title FHE-encrypted prompt storage
/// @notice Stores a prompt as encrypted UTF-8 bytes using FHEVM
contract FHEPromptContract is ZamaEthereumConfig {
    uint16 public constant MAX_LEN = 512;

    euint8[MAX_LEN] private _prompt;
    uint16 private _length;

    event PromptUpdated(address indexed sender, uint16 length);

    /// @param encryptedChars array of encrypted uint8 (UTF-8 bytes)
    /// @param length actual prompt length
    /// @param inputProof ZK proof binding ciphertexts to sender + contract
    function setPrompt(
        bytes32[] calldata encryptedChars,
        uint16 length,
        bytes calldata inputProof
    ) external {
        require(length <= MAX_LEN, "Prompt too long");
        require(encryptedChars.length >= length, "Invalid ciphertext array");

        _length = length;

        for (uint16 i = 0; i < length; i++) {
            // bytes32 → externalEuint8 handle
            externalEuint8 ext = externalEuint8.wrap(encryptedChars[i]);

            // verify proof + convert to native FHE type
            euint8 ch = FHE.fromExternal(ext, inputProof);

            _prompt[i] = ch;

            // ACL: allow contract + sender to decrypt off-chain
            FHE.allowThis(ch);
            FHE.allow(ch, msg.sender);
        }

        emit PromptUpdated(msg.sender, length);
    }

    /// @notice read encrypted character at index
    function getEncryptedChar(uint16 i) external view returns (euint8) {
        require(i < _length, "Out of bounds");
        return _prompt[i];
    }

    function length() external view returns (uint16) {
        return _length;
    }
}