package scan

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
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
		case *rsa.PublicKey:
			keyDesc = fmt.Sprintf("RSA-%d", k.N.BitLen())
		case *ecdsa.PublicKey:
			keyDesc = fmt.Sprintf("ECDSA-P-%d", k.Curve.Params().BitSize)
		case ed25519.PublicKey:
			keyDesc = "Ed25519"
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
		case *rsa.PublicKey:
			bits := k.N.BitLen()
			switch {
			case bits <= 1024:
				keyDesc = "RSA 1024"
			case bits <= 2048:
				keyDesc = "RSA 2048"
			case bits <= 4096:
				keyDesc = "RSA 4096"
			default:
				keyDesc = "RSA 8192+"
			}
		case *ecdsa.PublicKey:
			bits := k.Curve.Params().BitSize
			switch {
			case bits <= 256:
				keyDesc = "ECDSA P-256"
			case bits <= 384:
				keyDesc = "ECDSA P-384"
			default:
				keyDesc = "ECDSA P-521"
			}
		case ed25519.PublicKey:
			keyDesc = "Ed25519"
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

// aggregateOCSPMustStaple returns counts of certificates that carry the
// OCSP Must-Staple extension (RFC 7633) vs. those that do not.
func aggregateOCSPMustStaple(results *ScanResults) map[string]int {
	counts := map[string]int{"must-staple": 0, "not-must-staple": 0}
	oid := extensionOIDs["ocsp-must-staple"]
	for _, r := range results.Results {
		if !r.Success || len(r.Certificates) == 0 {
			continue
		}
		leaf := r.Certificates[0]
		found := false
		for _, ext := range leaf.Extensions {
			if ext.Id.Equal(oid) {
				found = true
				break
			}
		}
		if found {
			counts["must-staple"]++
		} else {
			counts["not-must-staple"]++
		}
	}
	return counts
}

// aggregateCertificateLifetimeTrends buckets certificate lifetimes around the
// CA/Browser Forum and Apple policy thresholds (90-day, 398-day, 825-day).
func aggregateCertificateLifetimeTrends(results *ScanResults) map[string]int {
	counts := map[string]int{
		"0-90":    0,
		"91-398":  0,
		"399-825": 0,
		"826+":    0,
	}
	for _, r := range results.Results {
		if !r.Success || len(r.Certificates) == 0 {
			continue
		}
		leaf := r.Certificates[0]
		days := int(leaf.NotAfter.Sub(leaf.NotBefore).Hours() / 24)
		switch {
		case days <= 90:
			counts["0-90"]++
		case days <= 398:
			counts["91-398"]++
		case days <= 825:
			counts["399-825"]++
		default:
			counts["826+"]++
		}
	}
	return counts
}

// aggregateForwardSecrecy counts certs whose negotiated cipher uses ECDHE/DHE.
func aggregateForwardSecrecy(results *ScanResults) map[string]int {
	counts := map[string]int{"forward-secret": 0, "not-forward-secret": 0}
	for _, r := range results.Results {
		if !r.Success {
			continue
		}
		if r.ForwardSecrecy {
			counts["forward-secret"]++
		} else {
			counts["not-forward-secret"]++
		}
	}
	return counts
}

// aggregateChainCompleteness counts certs that chain to a trusted root.
func aggregateChainCompleteness(results *ScanResults) map[string]int {
	counts := map[string]int{"complete": 0, "incomplete": 0}
	for _, r := range results.Results {
		if !r.Success || len(r.Certificates) == 0 {
			continue
		}
		if r.ChainComplete {
			counts["complete"]++
		} else {
			counts["incomplete"]++
		}
	}
	return counts
}

// aggregateRootCADistribution counts which root CA issued the certs.
func aggregateRootCADistribution(results *ScanResults) map[string]int {
	counts := make(map[string]int)
	for _, r := range results.Results {
		if !r.Success || len(r.Certificates) == 0 {
			continue
		}
		name := r.RootCA
		if name == "" {
			name = "Unknown"
		}
		counts[name]++
	}
	return counts
}

// aggregateKeyReuse counts domains whose leaf public key is shared by >1 domain.
func aggregateKeyReuse(results *ScanResults) map[string]int {
	counts := make(map[string]int)
	keyCount := make(map[string]int)
	for _, r := range results.Results {
		if !r.Success || r.KeyReuseHash == "" {
			continue
		}
		keyCount[r.KeyReuseHash]++
	}
	reused, unique := 0, 0
	for _, r := range results.Results {
		if !r.Success || r.KeyReuseHash == "" {
			continue
		}
		if keyCount[r.KeyReuseHash] > 1 {
			reused++
		} else {
			unique++
		}
	}
	counts["reused"] = reused
	counts["unique"] = unique
	return counts
}

// aggregateCTLogDiversity buckets by number of distinct CT logs.
func aggregateCTLogDiversity(results *ScanResults) map[string]int {
	counts := map[string]int{"0": 0, "1": 0, "2": 0, "3+": 0}
	for _, r := range results.Results {
		if !r.Success {
			continue
		}
		n := r.CTLogDiversity
		switch {
		case n <= 0:
			counts["0"]++
		case n == 1:
			counts["1"]++
		case n == 2:
			counts["2"]++
		default:
			counts["3+"]++
		}
	}
	return counts
}

// aggregateHSTS counts HSTS header presence.
func aggregateHSTS(results *ScanResults) map[string]int {
	counts := map[string]int{"hsts": 0, "no-hsts": 0}
	for _, r := range results.Results {
		if !r.Success {
			continue
		}
		if r.HSTS {
			counts["hsts"]++
		} else {
			counts["no-hsts"]++
		}
	}
	return counts
}

// aggregateCAA counts CAA record presence.
func aggregateCAA(results *ScanResults) map[string]int {
	counts := map[string]int{"caa": 0, "no-caa": 0}
	for _, r := range results.Results {
		if !r.Success {
			continue
		}
		if r.CAA {
			counts["caa"]++
		} else {
			counts["no-caa"]++
		}
	}
	return counts
}

// aggregateRC4 is always 0 (RC4 removed from modern TLS stacks).
func aggregateRC4(results *ScanResults) map[string]int {
	counts := map[string]int{"rc4": 0, "no-rc4": 0}
	for _, r := range results.Results {
		if !r.Success {
			continue
		}
		if r.RC4 {
			counts["rc4"]++
		} else {
			counts["no-rc4"]++
		}
	}
	return counts
}

// aggregateCRIME counts servers supporting TLS compression.
func aggregateCRIME(results *ScanResults) map[string]int {
	counts := map[string]int{"compression": 0, "no-compression": 0}
	for _, r := range results.Results {
		if !r.Success {
			continue
		}
		if r.CRIME {
			counts["compression"]++
		} else {
			counts["no-compression"]++
		}
	}
	return counts
}

// aggregateSecureRenegotiation counts secure renegotiation support.
func aggregateSecureRenegotiation(results *ScanResults) map[string]int {
	counts := map[string]int{"secure": 0, "insecure": 0}
	for _, r := range results.Results {
		if !r.Success {
			continue
		}
		if r.SecureRenegotiation {
			counts["secure"]++
		} else {
			counts["insecure"]++
		}
	}
	return counts
}

// aggregatePOODLE counts SSL 3.0 support (POODLE-vulnerable).
func aggregatePOODLE(results *ScanResults) map[string]int {
	counts := map[string]int{"vulnerable": 0, "not-vulnerable": 0}
	for _, r := range results.Results {
		if !r.Success {
			continue
		}
		if r.POODLE {
			counts["vulnerable"]++
		} else {
			counts["not-vulnerable"]++
		}
	}
	return counts
}

// aggregateFREAK is always 0 (export ciphers removed from modern tooling).
func aggregateFREAK(results *ScanResults) map[string]int {
	counts := map[string]int{"vulnerable": 0, "not-vulnerable": 0}
	for _, r := range results.Results {
		if !r.Success {
			continue
		}
		if r.FREAK {
			counts["vulnerable"]++
		} else {
			counts["not-vulnerable"]++
		}
	}
	return counts
}

// aggregateLogjam is always 0 (cannot be probed reliably).
func aggregateLogjam(results *ScanResults) map[string]int {
	counts := map[string]int{"vulnerable": 0, "not-vulnerable": 0}
	for _, r := range results.Results {
		if !r.Success {
			continue
		}
		if r.Logjam {
			counts["vulnerable"]++
		} else {
			counts["not-vulnerable"]++
		}
	}
	return counts
}

// aggregateECH counts ECH support via DNS HTTPS records.
func aggregateECH(results *ScanResults) map[string]int {
	counts := map[string]int{"ech": 0, "no-ech": 0}
	for _, r := range results.Results {
		if !r.Success {
			continue
		}
		if r.ECH {
			counts["ech"]++
		} else {
			counts["no-ech"]++
		}
	}
	return counts
}

// aggregatePQC counts servers supporting X25519MLKEM768.
func aggregatePQC(results *ScanResults) map[string]int {
	counts := map[string]int{"pqc": 0, "no-pqc": 0}
	for _, r := range results.Results {
		if !r.Success {
			continue
		}
		if r.PQC {
			counts["pqc"]++
		} else {
			counts["no-pqc"]++
		}
	}
	return counts
}

// aggregateIPv6 counts domains reachable over IPv6.
func aggregateIPv6(results *ScanResults) map[string]int {
	counts := map[string]int{"ipv6": 0, "ipv4-only": 0}
	for _, r := range results.Results {
		if !r.Success {
			continue
		}
		if r.IPv6 {
			counts["ipv6"]++
		} else {
			counts["ipv4-only"]++
		}
	}
	return counts
}

// aggregateIssuanceVolume counts certs issued in the last 7 days.
func aggregateIssuanceVolume(results *ScanResults) map[string]int {
	counts := map[string]int{"issued-last-7d": 0, "older": 0}
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	for _, r := range results.Results {
		if !r.Success || len(r.Certificates) == 0 {
			continue
		}
		if r.Certificates[0].NotBefore.After(cutoff) {
			counts["issued-last-7d"]++
		} else {
			counts["older"]++
		}
	}
	return counts
}
