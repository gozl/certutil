package certutil

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
)

// PublicKey is a thin wrapper for the public key implementation of selected 
// cryptographic algorithms.
type PublicKey struct {
	algorithm KeyAlgorithm
	isEC bool
	isRSA bool
	isEd25519 bool
	publicKey crypto.PublicKey
}

// Algorithm returns the public key algorithm.
func (pubkey *PublicKey) Algorithm() KeyAlgorithm {
	return pubkey.algorithm
}

// Encode marshals the public key to PEM encoded string. See the 
// ParsePublicKey method for unmarshaling PEM encoded public key to 
// a PublicKey instance.
func (pubkey *PublicKey) Encode() ([]byte, error) {
	keyBytes, err := x509.MarshalPKIXPublicKey(pubkey.publicKey)
	if err != nil {
		return nil, err
	}
	
	pemKey := new(bytes.Buffer)
	err = pem.Encode(pemKey, &pem.Block{
		Type: "PUBLIC KEY",
		Bytes: keyBytes,
	})
	if err != nil {
		return nil, err
	}

	return pemKey.Bytes(), nil
}
