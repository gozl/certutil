package certutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// PrivateKey is a thin wrapper for the private key implementation of selected 
// cryptographic algorithms.
type PrivateKey struct {
	algorithm KeyAlgorithm
	isEC bool
	isRSA bool
	isEd25519 bool
	ecPrivateKey *ecdsa.PrivateKey
	rsaPrivateKey *rsa.PrivateKey
	ed25519PrivateKey ed25519.PrivateKey
}

// ParsePrivateKey unmarshals a private key from PEM encoded data. See the 
// PrivateKey.Encode method for marshaling private key to PEM encoded string.
func ParsePrivateKey(pemkey []byte) (*PrivateKey, error) {
	block, _ := pem.Decode(pemkey)
	privkey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch k := privkey.(type) {
	case *ecdsa.PrivateKey:
		var algo KeyAlgorithm
		switch k.Params().Name {
		case "P-224":
			algo = P224
		case "P-256":
			algo = Prime256v1
		case "P-384":
			algo = Secp384r1
		case "P-521":
			algo = Secp521r1
		default:
			return nil, fmt.Errorf("encoded bytes is not supported EC private key")
		}

		return &PrivateKey{
			algorithm: algo,
			isEC: true,
			ecPrivateKey: k,
		}, nil
	case *rsa.PrivateKey:
		var algo KeyAlgorithm
		if k.Size() == 512 {
			algo = RSA4096
		} else if k.Size() == 256 {
			algo = RSA2048
		} else {
			return nil, fmt.Errorf("encoded bytes is not supported RSA private key")
		}
		return &PrivateKey{
			algorithm: algo,
			isRSA: true,
			rsaPrivateKey: k,
		}, nil
	case ed25519.PrivateKey:
		return &PrivateKey{
			algorithm: Ed25519,
			isEd25519: true,
			ed25519PrivateKey: k,
		}, nil
	default:
		return nil, fmt.Errorf("encoded bytes is not supported private key")
	}
}

// NewPrivateKey creates a new private key using algo as the cryptographic 
// algorithm.
func NewPrivateKey(algo KeyAlgorithm) (*PrivateKey, error) {
	switch algo {
	case P224, Prime256v1, Secp384r1, Secp521r1:
		privkey, err := newECPrivateKey(algo)
		if err != nil {
			return nil, err
		}
		return &PrivateKey{
			algorithm: algo,
			isEC: true,
			ecPrivateKey: privkey,
		}, nil
	case RSA2048, RSA4096:
		privkey, err := newRSAPrivateKey(algo)
		if err != nil {
			return nil, err
		}
		return &PrivateKey{
			algorithm: algo,
			isRSA: true,
			rsaPrivateKey: privkey,
		}, nil
	case Ed25519:
		privkey, err := newEd25519PrivateKey()
		if err != nil {
			return nil, err
		}
		return &PrivateKey{
			algorithm: algo,
			isEd25519: true,
			ed25519PrivateKey: privkey,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported key algorithm")
	}
}

// newECPrivateKey creates a private key using elliptic curve.
func newECPrivateKey(algo KeyAlgorithm) (*ecdsa.PrivateKey, error) {
	var privkey *ecdsa.PrivateKey
	var err error
	switch algo {
	case P224:
		privkey, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case Prime256v1:
		privkey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case Secp384r1:
		privkey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case Secp521r1:
		privkey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return nil, fmt.Errorf("unsupported EC algorithm")
	}
	if err != nil {
		return nil, err
	}

	return privkey, nil
}

// newRSAPrivateKey creates a private key using RSA.
func newRSAPrivateKey(algo KeyAlgorithm) (*rsa.PrivateKey, error) {
	rsaBits := 0
	switch algo {
	case RSA2048:
		rsaBits = 2048
	case RSA4096:
		rsaBits = 4096
	default:
		return nil, fmt.Errorf("unsupported RSA algorithm")
	}

	privkey, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, err
	}

	return privkey, nil
}

// newRSAPrivateKey creates a private key using Ed25519.
func newEd25519PrivateKey() (ed25519.PrivateKey, error) {
	_, privkey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return privkey, nil
}

// Encode marshals the private key to PEM encoded string. See the 
// ParsePrivateKey method for unmarshaling PEM encoded private key to 
// a PrivateKey instance.
func (privkey *PrivateKey) Encode() ([]byte, error) {
	var keyBytes []byte
	pemHeader := ""
	var err error

	if privkey.isEC {
		if privkey.ecPrivateKey == nil {
			return nil, fmt.Errorf("unable to encode an empty key")
		}
		pemHeader = "EC PRIVATE KEY"
		keyBytes, err = x509.MarshalPKCS8PrivateKey(privkey.ecPrivateKey)
		if err != nil {
			return nil, err
		}
	} else if privkey.isRSA {
		if privkey.rsaPrivateKey == nil {
			return nil, fmt.Errorf("unable to encode an empty key")
		}
		pemHeader = "RSA PRIVATE KEY"
		keyBytes, err = x509.MarshalPKCS8PrivateKey(privkey.rsaPrivateKey)
		if err != nil {
			return nil, err
		}
	} else if privkey.isEd25519 {
		if privkey.ed25519PrivateKey == nil {
			return nil, fmt.Errorf("unable to encode an empty key")
		}
		pemHeader = "PRIVATE KEY"
		keyBytes, err = x509.MarshalPKCS8PrivateKey(privkey.ed25519PrivateKey)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("unable to encode an empty key")
	}

	privkeyPEM := new(bytes.Buffer)
	err = pem.Encode(privkeyPEM, &pem.Block{
		Type: pemHeader,
		Bytes: keyBytes,
	})
	if err != nil {
		return nil, err
	}

	return privkeyPEM.Bytes(), nil
}

// Algorithm returns the private key algorithm.
func (privkey *PrivateKey) Algorithm() KeyAlgorithm {
	return privkey.algorithm
}

// Public returns the public key associated with this private key.
func (privkey *PrivateKey) Public() (*PublicKey, error) {
	if privkey.isEC {
		if privkey.ecPrivateKey == nil {
			return nil, fmt.Errorf("private key is empty")
		}
		return &PublicKey{
			publicKey: privkey.ecPrivateKey.Public(),
			isEC: true,
			algorithm: privkey.algorithm,
		}, nil
	} else if privkey.isRSA {
		if privkey.rsaPrivateKey == nil {
			return nil, fmt.Errorf("private key is empty")
		}
		return &PublicKey{
			publicKey: privkey.rsaPrivateKey.Public(),
			isRSA: true,
			algorithm: privkey.algorithm,
		}, nil
	} else if privkey.isEd25519 {
		if privkey.ed25519PrivateKey == nil {
			return nil, fmt.Errorf("private key is empty")
		}
		return &PublicKey{
			publicKey: privkey.ed25519PrivateKey.Public(),
			isEd25519: true,
			algorithm: privkey.algorithm,
		}, nil
	}
	panic("internal inconsistency: privkey__Public~1")
}

// EC returns the underlying EC private key.
func (privkey *PrivateKey) EC() (*ecdsa.PrivateKey, error) {
	if !privkey.isEC {
		return nil, fmt.Errorf("not an EC private key")
	}
	if privkey.ecPrivateKey == nil {
		return nil, fmt.Errorf("private key is empty")
	}
	return privkey.ecPrivateKey, nil
}

// RSA returns the underlying RSA private key.
func (privkey *PrivateKey) RSA() (*rsa.PrivateKey, error) {
	if !privkey.isRSA {
		return nil, fmt.Errorf("not a RSA private key")
	}
	if privkey.rsaPrivateKey == nil {
		return nil, fmt.Errorf("private key is empty")
	}
	return privkey.rsaPrivateKey, nil
}

// Ed25519 returns the underlying Ed25519 private key.
func (privkey *PrivateKey) Ed25519() (ed25519.PrivateKey, error) {
	if !privkey.isEd25519 {
		return nil, fmt.Errorf("not Ed25519 private key")
	}
	if privkey.ed25519PrivateKey == nil {
		return nil, fmt.Errorf("private key is empty")
	}
	return privkey.ed25519PrivateKey, nil
}
