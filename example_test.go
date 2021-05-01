package certutil_test

import (
	"fmt"
	"crypto/x509"
	"github.com/gozl/certutil"
)

func ExampleNewPrivateKey() {
	myKey, err := certutil.NewPrivateKey(certutil.Ed25519)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Printf("key algo: %s\n", myKey.Algorithm().String())

	// marshal private key to PEM encoded string
	myKeyPEM, err := myKey.Encode()
	if err != nil {
		fmt.Println(err.Error())
	}

	// unmarshal back
	myKey2, err := certutil.ParsePrivateKey(myKeyPEM)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Printf("key2 algo: %s\n", myKey2.Algorithm().String())

	// Output:
	// key algo: Ed25519
	// key2 algo: Ed25519
}

func ExampleNewRootCA() {
	caKey, err := certutil.NewPrivateKey(certutil.Ed25519)
	if err != nil {
		fmt.Println(err.Error())
	}

	caCertOpts := certutil.NewCertOptions().
		CN("FullTrust CA").
		KeyUsage(x509.KeyUsageCRLSign).
		ExtKeyUsage(x509.ExtKeyUsageMicrosoftKernelCodeSigning)

	caCertPEM, err := certutil.NewRootCA(caKey, caCertOpts)
	if err != nil {
		fmt.Println(err.Error())
	}

	// a PEM encoded cert is printable
	//fmt.Printf("CA cert:\n%s\n", caCertPEM)

	caCert, err := certutil.ParseCert(caCertPEM)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Printf("CA cert common name: %s\n", caCert.Subject.CommonName)

	// Output:
	// CA cert common name: FullTrust CA
}

func ExampleNewCert() {
	// create a CA first
	caKey, err := certutil.NewPrivateKey(certutil.Ed25519)
	if err != nil {
		fmt.Println(err.Error())
	}
	caCertOpts := certutil.NewCertOptions().CN("FullTrust CA")
	caCertPEM, err := certutil.NewRootCA(caKey, caCertOpts)
	if err != nil {
		fmt.Println(err.Error())
	}

	// create a user private key
	userKey, err := certutil.NewPrivateKey(certutil.Ed25519)
	if err != nil {
		fmt.Println(err.Error())
	}

	// now create a csr (certificate signing request) using the user's private 
	// key.
	userCertOpts := certutil.NewCertOptions().CN("example.com")
	userCSRPEM, err := certutil.NewCSR(userKey, userCertOpts)
	if err != nil {
		fmt.Println(err.Error())
	}

	userCSR, err := certutil.ParseCSR(userCSRPEM)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Printf("User CSR subject common name: %s\n", userCSR.Subject.CommonName)

	// sign the CSR using the CA's certificate and private key. Extra options 
	// can be specified with userCertOpts.
	userCertPEM, err := certutil.NewCert(userCSRPEM, caCertPEM, caKey, userCertOpts)
	if err != nil {
		fmt.Println(err.Error())
	}

	userCert, err := certutil.ParseCert(userCertPEM)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Printf("User cert subject common name: %s\n", userCert.Subject.CommonName)

	// Output:
	// User CSR subject common name: example.com
	// User cert subject common name: example.com
}