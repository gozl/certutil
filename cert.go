package certutil

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
)

// NewRootCA creates a self-signed CA certificate in PEM encoded format.
func NewRootCA(key *PrivateKey, opts *CertOption) ([]byte, error) {
	certOpts, errOpts := opts.Validate()
	if errOpts != nil {
		return nil, errOpts
	}

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature

	// Only RSA subject keys should have the KeyEncipherment KeyUsage bits set.
	// In the context of TLS this KeyUsage is particular to RSA key exchange 
	// and authentication.
	if key.Algorithm().IsRSA() {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	for _, v := range certOpts.keyUsage {
		if v == x509.KeyUsageDigitalSignature || v == x509.KeyUsageKeyEncipherment {
			continue
		}
		keyUsage |= v
	}

	// random serial
	serialNumber, err := newRandomCertSerial()
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: certOpts.subject,
		NotBefore: certOpts.notBefore,
		NotAfter:  certOpts.notAfter,
		BasicConstraintsValid: true,

		KeyUsage:    keyUsage,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},

		DNSNames:       []string{},
		EmailAddresses: []string{},
		URIs:           []*url.URL{},
		IPAddresses:    []net.IP{},
	}

	// CA must have these
	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageCertSign

	// add any custom eku
	for _, v := range certOpts.extKeyUsage {
		if v == x509.ExtKeyUsageServerAuth {
			continue
		}
		template.ExtKeyUsage = append(template.ExtKeyUsage, v)
	}

	// add SAN, email, IP and URLs if any
	if len(certOpts.san) != 0 {
		template.DNSNames = certOpts.san
	}
	if len(certOpts.emails) != 0 {
		template.EmailAddresses = certOpts.emails
	}
	if len(certOpts.urls) != 0 {
		template.URIs = certOpts.urls
	}
	if len(certOpts.ipaddrs) != 0 {
		template.IPAddresses = certOpts.ipaddrs
	}

	var derBytes []byte
	if key.Algorithm().IsEC() {
		priv, err := key.EC()
		if err != nil {
			return nil, err
		}
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
		if err != nil {
			return nil, err
		}
	} else if key.Algorithm().IsRSA() {
		priv, err := key.RSA()
		if err != nil {
			return nil, err
		}
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
		if err != nil {
			return nil, err
		}
	} else if key.Algorithm().IsEd25519() {
		priv, err := key.Ed25519()
		if err != nil {
			return nil, err
		}
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
		if err != nil {
			return nil, err
		}
	} else {
		panic("internal consistency: private_key_unexpected_algo")
	}

	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type: "CERTIFICATE",
		Bytes: derBytes,
	})
	if err != nil {
		return nil, err
	}

	return certPEM.Bytes(), nil
}

// NewCSR creates a new certificate signing request. Returns the PEM encoded 
// CSR string.
func NewCSR(key *PrivateKey, opts *CertOption) ([]byte, error) {
	certOpts, errOpts := opts.Validate()
	if errOpts != nil {
		return nil, errOpts
	}

	template := x509.CertificateRequest{
		Subject: certOpts.subject,
		DNSNames: []string{},
		EmailAddresses: []string{},
		URIs: []*url.URL{},
		IPAddresses: []net.IP{},
	}

	// add SAN, email, IP and URLs if any
	if len(certOpts.san) != 0 {
		template.DNSNames = certOpts.san
	}
	if len(certOpts.emails) != 0 {
		template.EmailAddresses = certOpts.emails
	}
	if len(certOpts.urls) != 0 {
		template.URIs = certOpts.urls
	}
	if len(certOpts.ipaddrs) != 0 {
		template.IPAddresses = certOpts.ipaddrs
	}

	var derBytes []byte
	if key.Algorithm().IsEC() {
		priv, err := key.EC()
		if err != nil {
			return nil, err
		}
		derBytes, err = x509.CreateCertificateRequest(rand.Reader, &template, priv)
		if err != nil {
			return nil, err
		}
	} else if key.Algorithm().IsRSA() {
		priv, err := key.RSA()
		if err != nil {
			return nil, err
		}
		derBytes, err = x509.CreateCertificateRequest(rand.Reader, &template, priv)
		if err != nil {
			return nil, err
		}
	} else if key.Algorithm().IsEd25519() {
		priv, err := key.Ed25519()
		if err != nil {
			return nil, err
		}
		derBytes, err = x509.CreateCertificateRequest(rand.Reader, &template, priv)
		if err != nil {
			return nil, err
		}
	} else {
		panic("internal consistency: private_key_unexpected_algo")
	}

	certPEM := new(bytes.Buffer)
	err := pem.Encode(certPEM, &pem.Block{
		Type: "CERTIFICATE REQUEST",
		Bytes: derBytes,
	})
	if err != nil {
		return nil, err
	}

	return certPEM.Bytes(), nil
}

// ParseCSR unmarshals the PEM encoded certificate signing request to a 
// x509.CertificateRequest instance.
func ParseCSR(pemcsr []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemcsr)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	return csr, nil
}

// NewCert creates a new certificate by signing the PEM encoded certificate 
// signing request pemcsr with a CA's credentials (pemCA and caKey). The  
// certificate can be customized by opts.
func NewCert(pemcsr []byte, pemCA []byte, caKey *PrivateKey, opts *CertOption) ([]byte, error) {
	certOpts, err := opts.Validate()
	if err != nil {
		return nil, err
	}

	// parse the CA's certificate
	caCert, err := ParseCert(pemCA)
	if err != nil {
		return nil, err
	}
	if !caCert.IsCA {
		return nil, fmt.Errorf("only CA can sign certificates")
	}

	// parse and validate CSR
	csr, err := ParseCSR(pemcsr)
	if err != nil {
		return nil, err
	}
	if err = csr.CheckSignature(); err != nil {
		return nil, err
	}

	// random serial
	serialNumber, err := newRandomCertSerial()
	if err != nil {
		return nil, err
	}

	// create client certificate template
	clientTemplate := x509.Certificate{
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		SerialNumber: serialNumber,
		Issuer:       caCert.Subject,
		Subject:      csr.Subject,
		NotBefore:    certOpts.notBefore,
		NotAfter:     certOpts.notAfter,

		ExtKeyUsage:  []x509.ExtKeyUsage{},

		DNSNames:       []string{},
		EmailAddresses: []string{},
		URIs:           []*url.URL{},
		IPAddresses:    []net.IP{},
	}

	// CA must have these
	if certOpts.isCA {
		// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
		// KeyUsage bits set in the x509.Certificate template
		caKeyUsage := x509.KeyUsageDigitalSignature
		for _, v := range certOpts.keyUsage {
			if v == x509.KeyUsageDigitalSignature || v == x509.KeyUsageCertSign {
				continue
			}
			caKeyUsage |= v
		}
		caKeyUsage |= x509.KeyUsageCertSign

		clientTemplate.IsCA = true
		clientTemplate.BasicConstraintsValid = true
		clientTemplate.KeyUsage = caKeyUsage
	} else {
		var keyUsage x509.KeyUsage
		if len(certOpts.keyUsage) == 0 {
			// default key usage
			keyUsage = x509.KeyUsageDigitalSignature
		} else {
			for _, v := range certOpts.keyUsage {
				keyUsage |= v
			}
		}
		clientTemplate.KeyUsage = keyUsage
	}

	// add any custom eku
	if len(certOpts.extKeyUsage) != 0 {
		for _, v := range certOpts.extKeyUsage {
			clientTemplate.ExtKeyUsage = append(clientTemplate.ExtKeyUsage, v)
		}
	} else {
		// default eku
		clientTemplate.ExtKeyUsage = []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		}
	}

	// add SAN, email, IP and URLs if any
	if len(certOpts.san) != 0 {
		clientTemplate.DNSNames = certOpts.san
	}
	if len(certOpts.emails) != 0 {
		clientTemplate.EmailAddresses = certOpts.emails
	}
	if len(certOpts.urls) != 0 {
		clientTemplate.URIs = certOpts.urls
	}
	if len(certOpts.ipaddrs) != 0 {
		clientTemplate.IPAddresses = certOpts.ipaddrs
	}

	var derBytes []byte
	if caKey.Algorithm().IsEC() {
		priv, err := caKey.EC()
		if err != nil {
			return nil, err
		}
		derBytes, err = x509.CreateCertificate(rand.Reader, &clientTemplate, caCert, priv.Public(), priv)
		if err != nil {
			return nil, err
		}
	} else if caKey.Algorithm().IsRSA() {
		priv, err := caKey.RSA()
		if err != nil {
			return nil, err
		}
		derBytes, err = x509.CreateCertificate(rand.Reader, &clientTemplate, caCert, priv.Public(), priv)
		if err != nil {
			return nil, err
		}
	} else if caKey.Algorithm().IsEd25519() {
		priv, err := caKey.Ed25519()
		if err != nil {
			return nil, err
		}
		derBytes, err = x509.CreateCertificate(rand.Reader, &clientTemplate, caCert, priv.Public(), priv)
		if err != nil {
			return nil, err
		}
	} else {
		panic("internal consistency: private_key_unexpected_algo")
	}

	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type: "CERTIFICATE",
		Bytes: derBytes,
	})
	if err != nil {
		return nil, err
	}

	return certPEM.Bytes(), nil
}

// ParseCert unmarshals the PEM encoded certificate to a x509.Certificate 
// instance.
func ParseCert(pemcert []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemcert)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// helpers

// newRandomCertSerial generates a random big.Int for certificate serial.
func newRandomCertSerial() (*big.Int, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNum, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}
	return serialNum, nil
}
