package scan

import (
	"crypto/tls"
	"encoding/asn1"
	"fmt"
	"strings"
	"time"
)

// Certificate Transparency extension OIDs
// (id-ct-signedCertificateTimestampList / id-ct-poison both live here)
var (
	oidCTSCTs        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	oidCTPrecertSCTs = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

// TLS version names
var tlsVersionNames = map[uint16]string{
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
	tls.VersionTLS12: "TLS 1.2",
	tls.VersionTLS13: "TLS 1.3",
}

// SSL version names (detected via openssl)
var sslVersionNames = map[string]string{
	"SSL3": "SSL 3.0",
}

// Cipher suite names (common ones)
var cipherSuiteNames = map[uint16]string{
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:            "TLS_RSA_WITH_AES_128_CBC_SHA",
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:            "TLS_RSA_WITH_AES_256_CBC_SHA",
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256:         "TLS_RSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384:         "TLS_RSA_WITH_AES_256_GCM_SHA384",
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
	tls.TLS_AES_128_GCM_SHA256:                  "TLS_AES_128_GCM_SHA256",
	tls.TLS_AES_256_GCM_SHA384:                  "TLS_AES_256_GCM_SHA384",
	tls.TLS_CHACHA20_POLY1305_SHA256:            "TLS_CHACHA20_POLY1305_SHA256",
}

// aggregateTLSVersions returns distribution of TLS/SSL versions negotiated/supported.
func aggregateTLSVersions(results *ScanResults) map[string]int {
	counts := make(map[string]int)
	for _, r := range results.Results {
		if !r.Success || r.Handshake == nil {
			continue
		}
		name := tlsVersionNames[r.Handshake.Version]
		if name == "" {
			name = fmt.Sprintf("Unknown (0x%04x)", r.Handshake.Version)
		}
		counts[name]++
		// Add SSL versions if detected
		for _, sslVer := range r.Handshake.SSLVersions {
			if sslName, ok := sslVersionNames[sslVer]; ok {
				counts[sslName]++
			}
		}
	}
	return counts
}

// aggregateCipherSuites returns distribution of cipher suites.
func aggregateCipherSuites(results *ScanResults) map[string]int {
	counts := make(map[string]int)
	for _, r := range results.Results {
		if !r.Success || r.Handshake == nil {
			continue
		}
		name := cipherSuiteNames[r.Handshake.CipherSuite]
		if name == "" {
			name = fmt.Sprintf("Unknown (0x%04x)", r.Handshake.CipherSuite)
		}
		counts[name]++
	}
	return counts
}

// aggregateKeyAlgorithms returns distribution of public key algorithms and sizes.
func aggregateKeyAlgorithms(results *ScanResults) map[string]int {
	counts := make(map[string]int)
	for _, r := range results.Results {
		if !r.Success || len(r.Certificates) == 0 {
			continue
		}
		leaf := r.Certificates[0]
		pub := leaf.PublicKey
		var keyDesc string

		switch k := pub.(type) {
		case interface{ Size() int }:
			keyDesc = fmt.Sprintf("%s-%d", leaf.PublicKeyAlgorithm, k.Size())
		default:
			keyDesc = leaf.PublicKeyAlgorithm.String()
		}
		counts[keyDesc]++
	}
	return counts
}

// aggregateSignatureAlgorithms returns distribution of signature algorithms.
func aggregateSignatureAlgorithms(results *ScanResults) map[string]int {
	counts := make(map[string]int)
	for _, r := range results.Results {
		if !r.Success || len(r.Certificates) == 0 {
			continue
		}
		leaf := r.Certificates[0]
		name := leaf.SignatureAlgorithm.String()
		counts[name]++
	}
	return counts
}

// aggregateValidityPeriods returns histogram of certificate lifetimes in days.
func aggregateValidityPeriods(results *ScanResults) map[string]int {
	buckets := map[string]int{
		"0-30":    0,
		"31-60":   0,
		"61-90":   0,
		"91-120":  0,
		"121-180": 0,
		"181-365": 0,
		"366-730": 0,
		"731+":    0,
	}

	for _, r := range results.Results {
		if !r.Success || len(r.Certificates) == 0 {
			continue
		}
		leaf := r.Certificates[0]
		days := int(leaf.NotAfter.Sub(leaf.NotBefore).Hours() / 24)

		switch {
		case days <= 30:
			buckets["0-30"]++
		case days <= 60:
			buckets["31-60"]++
		case days <= 90:
			buckets["61-90"]++
		case days <= 120:
			buckets["91-120"]++
		case days <= 180:
			buckets["121-180"]++
		case days <= 365:
			buckets["181-365"]++
		case days <= 730:
			buckets["366-730"]++
		default:
			buckets["731+"]++
		}
	}
	return buckets
}

// aggregateSANCounts returns histogram of SAN entry counts.
func aggregateSANCounts(results *ScanResults) map[string]int {
	buckets := make(map[string]int)
	for _, r := range results.Results {
		if !r.Success || len(r.Certificates) == 0 {
			continue
		}
		leaf := r.Certificates[0]
		count := len(leaf.DNSNames) + len(leaf.IPAddresses) + len(leaf.EmailAddresses) + len(leaf.URIs)
		key := fmt.Sprintf("%d", count)
		if count > 50 {
			key = "50+"
		}
		buckets[key]++
	}
	return buckets
}

// aggregateCAMarketShare returns distribution of issuing CAs.
func aggregateCAMarketShare(results *ScanResults) map[string]int {
	counts := make(map[string]int)
	for _, r := range results.Results {
		if !r.Success || len(r.Certificates) < 2 {
			continue
		}
		// Issuer is typically the second cert in chain
		issuer := r.Certificates[1].Subject.CommonName
		if issuer == "" {
			issuer = r.Certificates[1].Subject.Organization[0]
		}
		if issuer == "" {
			issuer = "Unknown"
		}
		// Clean up common suffixes
		issuer = cleanCAName(issuer)
		counts[issuer]++
	}
	return counts
}

func cleanCAName(name string) string {
	// Remove common suffixes
	suffixes := []string{" CA", " Root", " Intermediate", " Authority", " G1", " G2", " G3", " G4", " R1", " R2", " R3", " E1", " E2", " E3"}
	for _, s := range suffixes {
		if len(name) > len(s) && name[len(name)-len(s):] == s {
			name = name[:len(name)-len(s)]
		}
	}
	return name
}

// aggregateOCSPStapling returns OCSP stapling support.
func aggregateOCSPStapling(results *ScanResults) map[string]int {
	counts := map[string]int{"stapled": 0, "not-stapled": 0}
	for _, r := range results.Results {
		if !r.Success {
			continue
		}
		if r.OCSPStapled {
			counts["stapled"]++
		} else {
			counts["not-stapled"]++
		}
	}
	return counts
}

// aggregateCT returns Certificate Transparency participation.
func aggregateCT(results *ScanResults) map[string]int {
	counts := map[string]int{"with-scts": 0, "without-scts": 0}
	for _, r := range results.Results {
		if !r.Success || len(r.Certificates) == 0 {
			continue
		}
		leaf := r.Certificates[0]
		hasSCT := false
		for _, ext := range leaf.Extensions {
			if ext.Id.Equal(oidCTSCTs) || ext.Id.Equal(oidCTPrecertSCTs) {
				hasSCT = true
				break
			}
		}
		if hasSCT || len(r.Handshake.SCTs) > 0 {
			counts["with-scts"]++
		} else {
			counts["without-scts"]++
		}
	}
	return counts
}

// Extension OIDs we track
var extensionOIDs = map[string]asn1.ObjectIdentifier{
	"key-usage":             {2, 5, 29, 15},
	"extended-key-usage":    {2, 5, 29, 37},
	"basic-constraints":     {2, 5, 29, 19},
	"subject-key-id":        {2, 5, 29, 14},
	"authority-key-id":      {2, 5, 29, 35},
	"subject-alt-name":      {2, 5, 29, 17},
	"crl-distribution":      {2, 5, 29, 31},
	"authority-info-access": {1, 3, 6, 1, 5, 5, 7, 1, 1},
	"certificate-policies":  {2, 5, 29, 32},
	"ocsp-must-staple":      {1, 3, 6, 1, 5, 5, 7, 1, 24},
	"ct-precert-scts":       {1, 3, 6, 1, 4, 1, 11129, 2, 4, 2},
	"ct-scts":               {1, 3, 6, 1, 4, 1, 11129, 2, 4, 5},
}

// aggregateExtensions returns presence of key extensions.
func aggregateExtensions(results *ScanResults) map[string]int {
	counts := make(map[string]int)
	for name := range extensionOIDs {
		counts[name] = 0
	}

	for _, r := range results.Results {
		if !r.Success || len(r.Certificates) == 0 {
			continue
		}
		leaf := r.Certificates[0]

		for name, oid := range extensionOIDs {
			for _, ext := range leaf.Extensions {
				if ext.Id.Equal(oid) {
					counts[name]++
					break
				}
			}
		}
	}
	return counts
}

// aggregateKeySizes returns distribution of public key sizes.
func aggregateKeySizes(results *ScanResults) map[string]int {
	counts := make(map[string]int)
	for _, r := range results.Results {
		if !r.Success || len(r.Certificates) == 0 {
			continue
		}
		leaf := r.Certificates[0]
		pub := leaf.PublicKey
		var keyDesc string

		switch k := pub.(type) {
		case interface{ Size() int }:
			size := k.Size()
			switch leaf.PublicKeyAlgorithm.String() {
			case "RSA":
				if size <= 1024 {
					keyDesc = "RSA 1024"
				} else if size <= 2048 {
					keyDesc = "RSA 2048"
				} else if size <= 4096 {
					keyDesc = "RSA 4096"
				} else {
					keyDesc = "RSA 8192+"
				}
			case "ECDSA":
				if size <= 256 {
					keyDesc = "ECDSA P-256"
				} else if size <= 384 {
					keyDesc = "ECDSA P-384"
				} else {
					keyDesc = "ECDSA P-521"
				}
			default:
				keyDesc = fmt.Sprintf("%s-%d", leaf.PublicKeyAlgorithm, size)
			}
		default:
			keyDesc = leaf.PublicKeyAlgorithm.String()
		}
		counts[keyDesc]++
	}
	return counts
}

// aggregateHashAlgorithms returns distribution of certificate signature hash algorithms.
func aggregateHashAlgorithms(results *ScanResults) map[string]int {
	counts := make(map[string]int)
	for _, r := range results.Results {
		if !r.Success || len(r.Certificates) == 0 {
			continue
		}
		leaf := r.Certificates[0]
		alg := leaf.SignatureAlgorithm.String()
		// Extract hash part
		hash := "Unknown"
		if strings.Contains(alg, "SHA1") || strings.Contains(alg, "SHA-1") {
			hash = "SHA-1"
		} else if strings.Contains(alg, "SHA256") || strings.Contains(alg, "SHA-256") {
			hash = "SHA-256"
		} else if strings.Contains(alg, "SHA384") || strings.Contains(alg, "SHA-384") {
			hash = "SHA-384"
		} else if strings.Contains(alg, "SHA512") || strings.Contains(alg, "SHA-512") {
			hash = "SHA-512"
		} else if strings.Contains(alg, "MD5") {
			hash = "MD5"
		}
		counts[hash]++
	}
	return counts
}

// aggregateWildcardCerts returns wildcard vs non-wildcard certificate counts.
func aggregateWildcardCerts(results *ScanResults) map[string]int {
	counts := map[string]int{"wildcard": 0, "non-wildcard": 0}
	for _, r := range results.Results {
		if !r.Success || len(r.Certificates) == 0 {
			continue
		}
		leaf := r.Certificates[0]
		isWildcard := false
		for _, name := range leaf.DNSNames {
			if len(name) > 2 && name[:2] == "*." {
				isWildcard = true
				break
			}
		}
		if isWildcard {
			counts["wildcard"]++
		} else {
			counts["non-wildcard"]++
		}
	}
	return counts
}

// aggregateSelfSigned returns self-signed vs CA-signed certificate counts.
func aggregateSelfSigned(results *ScanResults) map[string]int {
	counts := map[string]int{"self-signed": 0, "ca-signed": 0}
	for _, r := range results.Results {
		if !r.Success || len(r.Certificates) == 0 {
			continue
		}
		leaf := r.Certificates[0]
		if leaf.Issuer.String() == leaf.Subject.String() {
			counts["self-signed"]++
		} else {
			counts["ca-signed"]++
		}
	}
	return counts
}

// aggregateExpiredCerts returns expired vs not-expired certificate counts.
func aggregateExpiredCerts(results *ScanResults) map[string]int {
	counts := map[string]int{"expired": 0, "not-expired": 0}
	now := time.Now()
	for _, r := range results.Results {
		if !r.Success || len(r.Certificates) == 0 {
			continue
		}
		leaf := r.Certificates[0]
		if now.After(leaf.NotAfter) {
			counts["expired"]++
		} else {
			counts["not-expired"]++
		}
	}
	return counts
}
