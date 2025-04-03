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

/*
Package xbin25 provides secure data serialization with encryption, digital signatures, and compression.

XBin25 combines AES-256-GCM encryption, RSA-OAEP key protection, RSA-PSS signatures,
and multi-layer compression to ensure data confidentiality, integrity, and authenticity.
It is designed for applications that require robust protection for sensitive data in transit
or at rest.

# Security Features

  - Confidentiality: AES-256-GCM encryption with unique keys per message
  - Integrity: AES-GCM authenticated encryption to prevent tampering
  - Authenticity: RSA-PSS digital signatures to verify the source
  - Replay protection: Timestamp verification with configurable window
  - Secure memory: Protected memory for cryptographic keys

# Basic Usage

Create a configuration:

	```
	config := xbin25.NewConfig(
		"encrypt-cert.pem",
		"encrypt-key.pem",
		"sign-cert.pem",
		"sign-key.pem",
		"application-context",
		30 * time.Minute,
		1024 * 1024,  // 1MB blocks per chunk
	)
	```

Marshall data:

	```
	data := map[string]interface{}{
		"username": "johndoe",
		"roles": []string{"admin", "user"},
	}

	encryptedData, err := config.Marshall(data)
	if err != nil {
		// Handle error
	}
	```

Unmarshall data:

	```
	decryptedData, err := config.Unmarshall(encryptedData)
	if err != nil {
		// Handle error
	}

	// Cast to expected type
	userData, ok := decryptedData.(map[string]interface{})
	```
*/

package xbin25
