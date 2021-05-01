package certutil

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/url"
	"time"
)

// CertOption builds certificate creation options in fluent pattern.
type CertOption struct {
	notBefore time.Time
	notAfter time.Time
	isCA bool
	subject pkix.Name
	san []string
	emails []string
	ipaddrsStr []string
	ipaddrs []net.IP
	urlsStr []string
	urls []*url.URL
	keyUsage []x509.KeyUsage
	extKeyUsage []x509.ExtKeyUsage
	basicConstraints bool
}

// NewCertOptions creates a new CertOption instance. Set parameters for the 
// CertOption instance by calling its various methods.
func NewCertOptions() *CertOption {
	return &CertOption{
		notBefore: time.Now(),
		notAfter: time.Now().Add(1*time.Hour),
		subject: pkix.Name{},
		san: []string{},
		emails: []string{},
		ipaddrsStr: []string{},
		urlsStr: []string{},
		keyUsage: []x509.KeyUsage{},
		extKeyUsage: []x509.ExtKeyUsage{},
	}
}

// CN sets the subject common name to name. Do not pass in an empty string. You 
// are required to set the common name.
func (certopt *CertOption) CN(name string) *CertOption {
	certopt.subject.CommonName = name
	return certopt
}

// Locality sets the subject locality. This is optional.
func (certopt *CertOption) Locality(name string) *CertOption {
	if name == "" {
		return certopt
	}
	certopt.subject.Locality = []string{name}
	return certopt
}

// Org sets the subject organization. This is optional.
func (certopt *CertOption) Org(name string) *CertOption {
	if name == "" {
		return certopt
	}
	certopt.subject.Organization = []string{name}
	return certopt
}

// Orgunit sets the subject organization unit. This is optional.
func (certopt *CertOption) Orgunit(name string) *CertOption {
	if name == "" {
		return certopt
	}
	certopt.subject.OrganizationalUnit = []string{name}
	return certopt
}

// Postcode sets the subject postal code. This is optional.
func (certopt *CertOption) Postcode(name string) *CertOption {
	if name == "" {
		return certopt
	}
	certopt.subject.PostalCode = []string{name}
	return certopt
}

// Street sets the subject street address. This is optional.
func (certopt *CertOption) Street(name string) *CertOption {
	if name == "" {
		return certopt
	}
	certopt.subject.StreetAddress = []string{name}
	return certopt
}

// Country sets the subject country. This is optional.
func (certopt *CertOption) Country(name string) *CertOption {
	if name == "" {
		return certopt
	}
	certopt.subject.Country = []string{name}
	return certopt
}

// CA indicates a certificate authority if isCA is true. A certificate 
// authority can sign other certificates.
func (certopt *CertOption) CA(isCA bool) *CertOption {
	certopt.isCA = isCA
	return certopt
}

// SAN sets the subject alternate names. This is optional.
func (certopt *CertOption) SAN(domains ...string) *CertOption {
	if len(domains) == 0 {
		return certopt
	}
	for _, v := range domains {
		if v != "" {
			certopt.san = append(certopt.san, v)
		}
	}

	certopt.san = certopt.dedupString(certopt.san)
	return certopt
}

// Email sets the subject email addresses. This is optional.
func (certopt *CertOption) Email(addrs ...string) *CertOption {
	if len(addrs) == 0 {
		return certopt
	}
	for _, v := range addrs {
		if v != "" {
			certopt.emails = append(certopt.emails, v)
		}
	}

	certopt.emails = certopt.dedupString(certopt.emails)
	return certopt
}

// Email sets the subject IP addresses. This is optional.
func (certopt *CertOption) IPAddr(ipaddrs ...string) *CertOption {
	if len(ipaddrs) == 0 {
		return certopt
	}
	for _, v := range ipaddrs {
		if v == "" {
			continue
		}
		certopt.ipaddrsStr = append(certopt.ipaddrsStr, v)
	}

	certopt.ipaddrsStr = certopt.dedupString(certopt.ipaddrsStr)
	return certopt
}

// URL sets the subject URIs. This is optional.
func (certopt *CertOption) URL(urls ...string) *CertOption {
	if len(urls) == 0 {
		return certopt
	}
	for _, v := range urls {
		if v != "" {
			certopt.urlsStr = append(certopt.urlsStr, v)
		}
	}

	certopt.urlsStr = certopt.dedupString(certopt.urlsStr)
	return certopt
}

// KeyUsage sets the certificate key usage. This is optional.
func (certopt *CertOption) KeyUsage(usage ...x509.KeyUsage) *CertOption {
	if len(usage) == 0 {
		return certopt
	}

	for _, v := range usage {
		certopt.keyUsage = append(certopt.keyUsage, v)
	}

	if len(certopt.keyUsage) == 0 {
		return certopt
	}

	// dedup
	dupmap := map[x509.KeyUsage]bool{}
	deduped := []x509.KeyUsage{}
	for i, _ := range certopt.keyUsage {
		if dupmap[certopt.keyUsage[i]] == true {
			// skip duplicate
		} else {
			dupmap[certopt.keyUsage[i]] = true
			deduped = append(deduped, certopt.keyUsage[i])
		}
	}
	certopt.keyUsage = deduped
	return certopt
}

// ExtKeyUsage sets the certificate extended key usage. This is optional.
func (certopt *CertOption) ExtKeyUsage(usage ...x509.ExtKeyUsage) *CertOption {
	if len(usage) == 0 {
		return certopt
	}

	for _, v := range usage {
		certopt.extKeyUsage = append(certopt.extKeyUsage, v)
	}

	if len(certopt.extKeyUsage) == 0 {
		return certopt
	}

	// dedup
	dupmap := map[x509.ExtKeyUsage]bool{}
	deduped := []x509.ExtKeyUsage{}
	for i, _ := range certopt.extKeyUsage {
		if dupmap[certopt.extKeyUsage[i]] == true {
			// skip duplicate
		} else {
			dupmap[certopt.extKeyUsage[i]] = true
			deduped = append(deduped, certopt.extKeyUsage[i])
		}
	}
	certopt.extKeyUsage = deduped
	return certopt
}

// NotBefore sets the time that the certificate is valid from. Defaults to the 
// time when calling NewCertOptions.
func (certopt *CertOption) NotBefore(timestamp time.Time) *CertOption {
	certopt.notBefore = timestamp
	return certopt
}

// NotAfter sets the time that the certificate will expire. Defaults to the 
// 1 hour from the time when calling NewCertOptions. If you prefer specifying 
// validity in terms of duration, use ValidFor.
func (certopt *CertOption) NotAfter(timestamp time.Time) *CertOption {
	certopt.notAfter = timestamp
	return certopt
}

// ValidFor sets the duration that the certificate will be valid for, starting 
// from NotBefore. Defaults to the 1 hour from the time when calling 
// NewCertOptions. If you prefering specifying validity in terms of expire 
// time, use NotAfter.
func (certopt *CertOption) ValidFor(period time.Duration) *CertOption {
	certopt.notAfter = certopt.notBefore.Add(period)
	return certopt
}

// Validate checks the current options for errors. You do not need to call this 
// method before creating a certificate.
func (certopt *CertOption) Validate() (*CertOption, error) {
	if certopt.subject.CommonName == "" {
		return nil, fmt.Errorf("subject CN is empty")
	}
	if certopt.notAfter.Before(certopt.notBefore) {
		return nil, fmt.Errorf("invalid expiry time")
	}

	// add IPs in any
	if len(certopt.ipaddrs) != 0 {
		certopt.ipaddrs = []net.IP{}
		for _, v := range certopt.ipaddrsStr {
			vip := net.ParseIP(v)
			if vip == nil {
				return nil, fmt.Errorf("invalid IP address")
			}
			certopt.ipaddrs = append(certopt.ipaddrs, vip)
		}
	}

	// add URLs in any
	if len(certopt.urlsStr) != 0 {
		certopt.urls = []*url.URL{}
		for _, v := range certopt.urlsStr {
			vURL, err := url.Parse(v)
			if err != nil {
				return nil, fmt.Errorf("invalid URL: %v", err)
			}
			certopt.urls = append(certopt.urls, vURL)
		}
	}

	return certopt, nil
}

// helpers

// dedupString is helper method to dedup a string slice.
func (certopt *CertOption) dedupString(strSlice []string) []string {
	if len(strSlice) == 0 {
		return []string{}
	}

	dupmap := map[string]bool{}
	deduped := []string{}
	for i, _ := range strSlice {
		if dupmap[strSlice[i]] == true {
			// skip duplicate
		} else {
			dupmap[strSlice[i]] = true
			deduped = append(deduped, strSlice[i])
		}
	}
	return deduped
}