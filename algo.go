package certutil

// KeyAlgorithm is certificate cryptographic algorithm.
type KeyAlgorithm int

const (
	// RSA2048 is RSA with 2048-bit long modulus.
	RSA2048 KeyAlgorithm = iota
	// RSA2048 is RSA with 4096-bit long modulus.
	RSA4096
	// P224 is an Ecdsa curve which implements P-224 (see FIPS 186-3, section 
	// D.2.2).
	P224
	// Prime256v1 is Ecdsa curve which implements NIST P-256 (FIPS 186-3, 
	// section D.2.3), also known as secp256r1 or prime256v1.
	Prime256v1
	// Secp384r1 is Ecdsa curve which implements NIST P-384 (FIPS 186-3, 
	// section D.2.4), also known as secp384r1.
	Secp384r1
	// Secp521r1 is Ecdsa curve which implements NIST P-521 (FIPS 186-3, 
	// section D.2.5), also known as secp521r1.
	Secp521r1
	// Ed25519 is Ed25519 signature algorithm (see https://ed25519.cr.yp.to).
	Ed25519
)

// String returns the string representation of algo.
func (algo KeyAlgorithm) String() string {
	switch algo {
	case RSA2048:
		return "RSA2048"
	case RSA4096:
		return "RSA4096"
	case P224:
		return "P224"
	case Prime256v1:
		return "Prime256v1"
	case Secp384r1:
		return "Secp384r1"
	case Secp521r1:
		return "Secp521r1"
	case Ed25519:
		return "Ed25519"
	default:
		panic("internal inconsistency: KeyAlgorithm__String~1")
	}
}

// IsEC returns true if algo is based on elliptic curve encryption.
func (algo KeyAlgorithm) IsEC() bool {
	switch algo {
	case P224, Prime256v1, Secp384r1, Secp521r1:
		return true
	default:
		return false
	}
}

// IsRSA returns true if algo is based on RSA encryption.
func (algo KeyAlgorithm) IsRSA() bool {
	switch algo {
	case RSA2048, RSA4096:
		return true
	default:
		return false
	}
}

// IsEd25519 returns true if algo is Ed25519.
func (algo KeyAlgorithm) IsEd25519() bool {
	if algo == Ed25519 {
		return true
	}
	return false
}