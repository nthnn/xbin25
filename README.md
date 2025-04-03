# XBin25 - Secure Data Serialization for Go

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

XBin25 is a Go package designed for secure data serialization, combining state-of-the-art encryption, digital signatures, and multi-layer compression. It ensures confidentiality, integrity, and authenticity for sensitive data in transit or at rest.

## Features

- **Military-Grade Encryption**: AES-256-GCM encryption with unique per-message keys
- **Secure Key Exchange**: RSA-OAEP for AES key encryption (3072-bit or stronger)
- **Tamper Evidence**: RSA-PSS digital signatures for data authenticity
- **Compression Layers**: Parallelized zstd (inner) and pgzip (outer) compression
- **Replay Protection**: Configurable timestamp validity windows
- **Memory Hardening**: Sensitive keys guarded by `memguard` against memory leaks
- **Modern Serialization**: Efficient MessagePack encoding for structured data

## Installation

```bash
go get github.com/nthnn/xbin25
```

## Dependencies

- Go 1.20+
- `memguard` (secure memory)
- `msgpack/v5` (serialization)
- `pgzip/zstd` (compression)
- `rsa/aes` (crypto primitives)

## Usage

### Basic Usage

```go
import "github.com/nthnn/xbin25"

func main() {
    // Initialize configuration
    config := xbin25.NewConfig(
        "encrypt-cert.pem",  // RSA public key for encryption
        "encrypt-key.pem",   // RSA private key for decryption
        "sign-cert.pem",     // RSA public key for signature verification
        "sign-key.pem",      // RSA private key for signing
        "user-auth-system",  // Context label
        30*time.Minute,      // Max message age
        1024*1024,           // 1MB compression blocks
    )

    // Marshall sensitive data
    data := map[string]interface{}{
        "session_id": "7a4e3b1c-89f2-4d65-9128-cc9a4b1d0e7f",
        "permissions": []string{"read:logs", "write:config"},
    }

    encryptedData, err := config.Marshall(data)
    if err != nil {
        panic(err)
    }

    // Unmarshall securely
    decrypted, err := config.Unmarshall(encryptedData)
    if err != nil {
        panic(err)
    }

    restored := decrypted.(map[string]interface{})
}
```

### Configuration Guide

#### XBin25Config Parameters

| Parameter	            | Description                                                               |
|-----------------------|---------------------------------------------------------------------------|
| EncryptCertFile       | Path to PEM-encoded X.509 certificate with RSA public key for encryption  |
| EncryptKeyFile	    | Path to PEM-encoded RSA private key for decryption                        |
| SignCertFile	        | Path to PEM-encoded X.509 certificate for signature verification          |
| SignKeyFile	        | Path to PEM-encoded RSA private key for signing                           |
| BlockSize	            | Compression block size (typically 1MB-4MB)                                |
| Label                 | Auto-derived from label string (SHA-256 hash of provided label)           |
| Duration              | Maximum allowed message age (e.g., 30*time.Minute)                        |

### Security Architecture

#### Marshalling Process

1. MessagePack serialization
2. AES-256-GCM encryption with random key
3. RSA-OAEP encryption of AES key
4. zstd compression
5. RSA-PSS signing
6. Timestamp embedding
7. pgzip outer compression

#### Unmarshalling Process

1. pgzip decompression
2. Timestamp validation
3. RSA-PSS signature verification
4. zstd decompression
5. RSA-OAEP decryption
6. AES-GCM decryption
7. MessagePack deserialization

### Best Practices

1. **Key Management**

    - Use 4096-bit RSA keys minimum
    - Store private keys in hardware security modules (HSMs) where possible
    - Rotate signing keys quarterly

2. **Operational Security**

    - Keep system clocks synchronized (NTP)
    - Use unique labels for different data contexts
    - Set conservative duration windows (15-60 minutes)

3. **Performance Tuning**

    - Adjust BlockSize based on payload characteristics
    - Balance between zstd compression level and CPU usage
    - Utilize hardware-accelerated AES (AES-NI)

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.

```
Copyright 2025 Nathanne Isip

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
