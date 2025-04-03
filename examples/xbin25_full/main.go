package main

import (
	"fmt"
	"os"
	"time"

	"github.com/nthnn/xbin25"
)

func main() {
	original := map[string]interface{}{
		"username": "alice",
		"email":    "alice@example.com",
		"age":      30,
	}

	xbinConfig := xbin25.NewConfig(
		"certs/encrypt_cert.pem",
		"certs/encrypt_key.pem",
		"certs/sign_cert.pem",
		"certs/sign_key.pem",
		"test",
		5*time.Minute,
		10,
	)

	encEnvelope, err := xbinConfig.Marshall(original)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error in Marshall: %v\n", err)
		return
	}

	fmt.Printf("Encrypted data: %+v\n", string(encEnvelope))
	fmt.Printf("Envelope data (%d bytes)\n", len(encEnvelope))

	decrypted, err := xbinConfig.Unmarshall(encEnvelope)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error in Unmarshall: %v\n", err)
		return
	}

	fmt.Printf("Decrypted data: %+v\n", decrypted)
}
