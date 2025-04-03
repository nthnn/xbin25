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
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/awnumar/memguard"
	"github.com/klauspost/compress/zstd"
	"github.com/klauspost/pgzip"
	"github.com/vmihailenco/msgpack/v5"
)

// Unmarshall decrypts, verifies, and deserializes binary data produced by the Marshall function.
//
// The process involves:
//  1. Decompression of the outer pgzip layer
//  2. Deserialization of the envelope structure
//  3. Timestamp verification for replay protection
//  4. RSA-PSS signature verification
//  5. Decompression of the zstd layer
//  6. RSA-OAEP decryption of the AES key
//  7. AES-GCM decryption of the data
//  8. MessagePack deserialization of the plaintext
//
// Parameters:
//   - data: Binary data previously produced by Marshall
//
// Returns:
//   - interface{}: The unmarshalled Go value
//   - error: An error if any step in the process fails
func (config *XBin25Config) Unmarshall(data []byte) (interface{}, error) {
	pubKey, err := loadCertificate(config.SignCertFile)
	if err != nil {
		return nil, err
	}

	privKey, err := loadPrivateKey(config.EncryptKeyFile)
	if err != nil {
		return nil, err
	}

	dataBuf := bytes.NewReader(data)
	decoderOuter, err := pgzip.NewReaderN(
		dataBuf,
		config.BlockSize,
		len(data)/config.BlockSize,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create outer zstd decoder: %w", err)
	}
	defer decoderOuter.Close()

	decompressedData, err := io.ReadAll(decoderOuter)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress outer data: %w", err)
	}

	var envelope signedCompressedData
	if err := msgpack.Unmarshal(decompressedData, &envelope); err != nil {
		return nil, fmt.Errorf("failed to MessagePack-decode envelope: %w", err)
	}

	now := time.Now()
	if envelope.Timestamp.After(now) || now.Sub(envelope.Timestamp) > config.Duration {
		return nil, errors.New("message timestamp is outside the allowed replay window")
	}

	hash := sha256.Sum256(envelope.Payload)
	if err := rsa.VerifyPSS(
		pubKey,
		crypto.SHA256,
		hash[:],
		envelope.Signature,
		nil,
	); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	decoder, err := zstd.NewReader(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create zstd decoder: %w", err)
	}
	defer decoder.Close()

	decompData, err := decoder.DecodeAll(envelope.Payload, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress data: %w", err)
	}

	var encData encryptedData
	if err := msgpack.Unmarshal(decompData, &encData); err != nil {
		return nil, fmt.Errorf("failed to MessagePack-decode encrypted data: %w", err)
	}

	aesKeyBytes, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		privKey,
		encData.EncryptedKey,
		[]byte(config.Label),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AES key: %w", err)
	}

	aesKeyBuf := memguard.NewBufferFromBytes(aesKeyBytes)
	for i := range aesKeyBytes {
		aesKeyBytes[i] = 0
	}
	defer aesKeyBuf.Destroy()

	block, err := aes.NewCipher(aesKeyBuf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM: %w", err)
	}

	plainData, err := gcm.Open(nil, encData.Nonce, encData.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	var out interface{}
	if err := msgpack.Unmarshal(plainData, &out); err != nil {
		return nil, fmt.Errorf("failed to MessagePack-decode plain data: %w", err)
	}

	return out, nil
}
