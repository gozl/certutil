package certutil

import (
	"testing"
)

func TestECPrivateKey(t *testing.T) {
	ecalgos := []KeyAlgorithm{
		P224,
		Prime256v1,
		Secp384r1,
		Secp521r1,
	}

	for _, algo := range ecalgos {
		privkey, err := NewPrivateKey(algo)
		if err != nil {
			t.Fatalf("Unexpected error creating %s private key: %v", 
				algo.String(), err)
		}

		privkeyPEM, err := privkey.Encode()
		if err != nil {
			t.Fatalf("Unexpected error encoding %s private key: %v", 
				algo.String(), err)
		}

		_, err = ParsePrivateKey(privkeyPEM)
		if err != nil {
			t.Fatalf("Unexpected error parsing %s private key: %v", 
				algo.String(), err)
		}
	}
}

func TestRSAPrivateKey(t *testing.T) {
	rsaalgos := []KeyAlgorithm{
		RSA2048,
		RSA4096,
	}

	for _, algo := range rsaalgos {
		privkey, err := NewPrivateKey(algo)
		if err != nil {
			t.Fatalf("Unexpected error creating %s private key: %v", 
				algo.String(), err)
		}

		privkeyPEM, err := privkey.Encode()
		if err != nil {
			t.Fatalf("Unexpected error encoding %s private key: %v", 
				algo.String(), err)
		}

		_, err = ParsePrivateKey(privkeyPEM)
		if err != nil {
			t.Fatalf("Unexpected error parsing %s private key: %v", 
				algo.String(), err)
		}
	}
}

func TestEd25519PrivateKey(t *testing.T) {
	privkey, err := NewPrivateKey(Ed25519)
	if err != nil {
		t.Fatalf("Unexpected error creating %s private key: %v", "ed25519", err)
	}

	privkeyPEM, err := privkey.Encode()
	if err != nil {
		t.Fatalf("Unexpected error encoding %s private key: %v", "ed25519", err)
	}

	_, err = ParsePrivateKey(privkeyPEM)
	if err != nil {
		t.Fatalf("Unexpected error parsing %s private key: %v", "ed25519", err)
	}
}