/*
 * Copyright 2025 Nathanne Isip
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package xbin25

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/awnumar/memguard"
)

// `XBin25Config` holds all configuration parameters for encryption and decryption.
// A single configuration can be used for multiple Marshall/Unmarshall operations.
type XBin25Config struct {
	// `EncryptCertFile` is the path to the certificate file containing the public key used for encryption.
	EncryptCertFile string

	// `EncryptKeyFile` is the path to the private key file used for decryption.
	EncryptKeyFile string

	// `SignCertFile` is the path to the certificate file containing the public key used for signature verification.
	SignCertFile string

	// `SignKeyFile` is the path to the private key file used for signing.
	SignKeyFile string

	// `BlockSize` specifies the block size for parallel compression algorithms.
	// Larger values can improve compression speed on multi-core systems at the cost of memory usage.
	BlockSize int

	// `Label` is a context parameter for RSA-OAEP encryption.
	// This is automatically derived from the labelStr parameter in NewConfig.
	Label string

	// `Duration` specifies the maximum allowed age for messages.
	// Messages older than this duration will be rejected, protecting against replay attacks.
	Duration time.Duration
}

// `encryptedData` is an internal structure representing the encrypted message.
type encryptedData struct {
	// `EncryptedKey` is the AES key encrypted with RSA-OAEP.
	EncryptedKey []byte

	// `Nonce` is the initialization vector for AES-GCM.
	Nonce []byte

	// `Ciphertext` is the AES-GCM encrypted data.
	Ciphertext []byte
}

// `signedCompressedData` is an internal structure containing the signed and compressed message.
type signedCompressedData struct {
	// `Payload` is the compressed and encrypted data.
	Payload []byte

	// `Signature` is the RSA-PSS signature of the `Payload`.
	Signature []byte

	// `Timestamp` indicates when the message was created, used for replay protection.
	Timestamp time.Time
}

// NewConfig creates a new `XBin25Config` with the provided parameters.
//
// Parameters:
//   - `encryptCertFile`: Path to the certificate file containing the public key used for encryption
//   - `encryptKeyFile`: Path to the private key file used for decryption
//   - `signCertFile`: Path to the certificate file containing the public key used for signature verification
//   - `signKeyFile`: Path to the private key file used for signing
//   - `labelStr`: A string label that is hashed and used as context for RSA-OAEP encryption
//   - `duration`: Maximum allowed age for messages (for replay protection)
//   - `blockSize`: Block size for parallel compression algorithms
//
// The function initializes `memguard` to protect sensitive cryptographic material in memory.
func NewConfig(
	encryptCertFile,
	encryptKeyFile,
	signCertFile,
	signKeyFile,
	labelStr string,
	duration time.Duration,
	blockSize int,
) *XBin25Config {
	memguard.CatchInterrupt()

	hasher := sha256.New()
	return &XBin25Config{
		EncryptCertFile: encryptCertFile,
		EncryptKeyFile:  encryptKeyFile,
		SignCertFile:    signCertFile,
		SignKeyFile:     signKeyFile,
		Duration:        duration,
		BlockSize:       blockSize,
		Label: hex.EncodeToString(
			hasher.Sum([]byte(labelStr)),
		),
	}
}
