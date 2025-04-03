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
	"fmt"
	"time"

	"github.com/awnumar/memguard"
	"github.com/klauspost/compress/zstd"
	"github.com/klauspost/pgzip"
	"github.com/vmihailenco/msgpack/v5"
)

// Marshall converts any serializable Go data structure into a secure binary format.
//
// The process involves:
//  1. MessagePack encoding of the input data
//  2. AES-256-GCM encryption with a random key
//  3. RSA-OAEP encryption of the AES key
//  4. zstd compression of the encrypted package
//  5. RSA-PSS signature of the compressed data
//  6. Timestamping for replay protection
//  7. Final compression with parallel gzip
//
// Parameters:
//   - `data`: Any Go value that can be serialized by MessagePack
//
// Returns:
//   - `[]byte`: The marshalled, encrypted, signed, and compressed data
//   - `error`: An error if any step in the process fails
func (config *XBin25Config) Marshall(data interface{}) ([]byte, error) {
	pubKey, err := loadCertificate(config.EncryptCertFile)
	if err != nil {
		return nil, err
	}

	privKey, err := loadPrivateKey(config.SignKeyFile)
	if err != nil {
		return nil, err
	}

	plainData, err := msgpack.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to MessagePack-encode data: %w", err)
	}

	aesKeyBuf := memguard.NewBufferRandom(32)
	defer aesKeyBuf.Destroy()

	block, err := aes.NewCipher(aesKeyBuf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plainData, nil)
	encryptedKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		pubKey,
		aesKeyBuf.Bytes(),
		[]byte(config.Label),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to encrypt AES key: %w", err)
	}

	encData := encryptedData{
		EncryptedKey: encryptedKey,
		Nonce:        nonce,
		Ciphertext:   ciphertext,
	}

	encryptedDataBytes, err := msgpack.Marshal(encData)
	if err != nil {
		return nil, fmt.Errorf("failed to MessagePack-encode encrypted data: %w", err)
	}

	var compBuf bytes.Buffer
	encoder, err := zstd.NewWriter(&compBuf)

	if err != nil {
		return nil, fmt.Errorf("failed to create zstd encoder: %w", err)
	}

	if _, err := encoder.Write(encryptedDataBytes); err != nil {
		return nil, fmt.Errorf("failed to compress data: %w", err)
	}

	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("failed to close compression encoder: %w", err)
	}

	payload := compBuf.Bytes()
	hash := sha256.Sum256(payload)

	signature, err := rsa.SignPSS(
		rand.Reader,
		privKey,
		crypto.SHA256,
		hash[:],
		nil,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to sign compressed payload: %w", err)
	}

	envelope := signedCompressedData{
		Payload:   payload,
		Signature: signature,
		Timestamp: time.Now(),
	}

	envelopeBytes, err := msgpack.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to MessagePack-encode envelope: %w", err)
	}

	var finalCompBuf bytes.Buffer
	gzipEncoder := pgzip.NewWriter(&finalCompBuf)
	gzipEncoder.SetConcurrency(
		config.BlockSize,
		len(envelopeBytes)/config.BlockSize,
	)

	if _, err := gzipEncoder.Write(envelopeBytes); err != nil {
		return nil, fmt.Errorf("failed to compress envelope: %w", err)
	}

	if err := gzipEncoder.Close(); err != nil {
		return nil, fmt.Errorf("failed to close zstd encoder: %w", err)
	}

	return finalCompBuf.Bytes(), nil
}
