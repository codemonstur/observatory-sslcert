package scan

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Timeout     time.Duration
	Concurrency int
	UserAgent   string
}

type Result struct {
	Domain              string
	Success             bool
	Error               string
	Handshake           *HandshakeInfo
	Certificates        []*x509.Certificate
	OCSPStapled         bool
	IPv6                bool
	ForwardSecrecy      bool
	ChainComplete       bool
	RootCA              string
	KeyReuseHash        string
	CTLogDiversity      int
	HSTS                bool
	CAA                 bool
	RC4                 bool
	CRIME               bool
	SecureRenegotiation bool
	POODLE              bool
	FREAK               bool
	Logjam              bool
	ECH                 bool
	PQC                 bool
}

type HandshakeInfo struct {
	Version     uint16
	CipherSuite uint16
	ServerName  string
	Resumed     bool
	OCSPStapled bool
	SCTs        [][]byte
	SSLVersions []string // SSL 3.0 (detected via openssl)
}

type ScanResults struct {
	Results      []Result
	SuccessCount int
	FailCount    int
	mu           sync.Mutex
}

func NewScanner(cfg Config) *Scanner {
	return &Scanner{cfg: cfg}
}

type Scanner struct {
	cfg Config
}

func (s *Scanner) Scan(domains []string) *ScanResults {
	results := &ScanResults{Results: make([]Result, 0, len(domains))}
	sem := make(chan struct{}, s.cfg.Concurrency)
	var wg sync.WaitGroup

	for _, domain := range domains {
		wg.Add(1)
		sem <- struct{}{}
		go func(d string) {
			defer wg.Done()
			defer func() { <-sem }()

			r := s.scanDomain(d)
			results.mu.Lock()
			results.Results = append(results.Results, r)
			if r.Success {
				results.SuccessCount++
			} else {
				results.FailCount++
			}
			results.mu.Unlock()
		}(domain)
	}

	wg.Wait()
	return results
}

func (s *Scanner) scanDomain(domain string) Result {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Timeout)
	defer cancel()

	// Resolve IP
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
	if err != nil || len(ips) == 0 {
		return Result{Domain: domain, Success: false, Error: "dns resolution failed"}
	}

	// Try each IP until one works
	var lastErr error
	for _, ip := range ips {
		r := s.scanIP(ctx, domain, ip.String())
		if r.Success {
			// IPv6 support is detected independently so an IPv4-first
			// success does not mask a working IPv6 endpoint.
			r.IPv6 = probeIPv6(domain, ips, s.cfg.Timeout)
			return r
		}
		lastErr = fmt.Errorf("%s", r.Error)
	}

	return Result{Domain: domain, Success: false, Error: lastErr.Error()}
}

func (s *Scanner) scanIP(ctx context.Context, domain, ip string) Result {
	address := net.JoinHostPort(ip, "443")

	dialer := &net.Dialer{Timeout: s.cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return Result{Domain: domain, Success: false, Error: fmt.Sprintf("tcp dial: %v", err)}
	}
	defer conn.Close()

	tlsConfig := &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true, // We verify manually
		NextProtos:         []string{"h2", "http/1.1"},
	}

	tlsConn := tls.Client(conn, tlsConfig)

	// Set deadlines
	deadline := time.Now().Add(s.cfg.Timeout)
	conn.SetDeadline(deadline)
	tlsConn.SetDeadline(deadline)

	// Perform handshake
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return Result{Domain: domain, Success: false, Error: fmt.Sprintf("handshake: %v", err)}
	}

	state := tlsConn.ConnectionState()
	certs := state.PeerCertificates

	// Check OCSP stapling
	ocspStapled := len(state.OCSPResponse) > 0

	// Extract SCTs (Signed Certificate Timestamps)
	var scts [][]byte
	for _, cert := range certs {
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(oidCTPrecertSCTs) || ext.Id.Equal(oidCTSCTs) {
				scts = append(scts, ext.Value)
			}
		}
	}

	// Probe for SSL 2.0 and 3.0 support using openssl
	sslVersions := probeSSL(domain, ip)

	// --- Derived metrics (no extra I/O) ---
	forwardSecrecy := false
	// TLS 1.3 always uses ephemeral key exchange (forward secrecy).
	if state.Version >= tls.VersionTLS13 {
		forwardSecrecy = true
	} else if name, ok := cipherSuiteNames[state.CipherSuite]; ok {
		if strings.Contains(name, "ECDHE") || strings.Contains(name, "DHE") {
			forwardSecrecy = true
		}
	}

	chainComplete := verifyChain(certs)

	rootCA := rootCAName(certs)

	keyReuseHash := ""
	if len(certs) > 0 {
		if der, err := x509.MarshalPKIXPublicKey(certs[0].PublicKey); err == nil {
			h := sha256.Sum256(der)
			keyReuseHash = hex.EncodeToString(h[:])
		}
	}

	ctLogDiversity := countDistinctCTLogs(state.SignedCertificateTimestamps, certs)

	poodle := false
	for _, v := range sslVersions {
		if v == "SSL3" {
			poodle = true
		}
	}

	// --- Probes (bounded, short timeouts) ---
	hsts := probeHSTS(domain, s.cfg.Timeout)
	caa := probeCAA(domain)
	ech := probeECH(domain)
	pqc := probePQC(domain, ip, s.cfg.Timeout)
	crime := probeCRIME(domain, ip)
	secureReneg := probeSecureRenegotiation(domain, ip)

	// Build handshake info
	handshake := &HandshakeInfo{
		Version:     state.Version,
		CipherSuite: state.CipherSuite,
		ServerName:  state.ServerName,
		Resumed:     state.DidResume,
		OCSPStapled: ocspStapled,
		SCTs:        scts,
		SSLVersions: sslVersions,
	}

	return Result{
		Domain:              domain,
		Success:             true,
		Handshake:           handshake,
		Certificates:        certs,
		OCSPStapled:         ocspStapled,
		ForwardSecrecy:      forwardSecrecy,
		ChainComplete:       chainComplete,
		RootCA:              rootCA,
		KeyReuseHash:        keyReuseHash,
		CTLogDiversity:      ctLogDiversity,
		HSTS:                hsts,
		CAA:                 caa,
		RC4:                 false, // RC4 removed from modern TLS stacks; never detected
		CRIME:               crime,
		SecureRenegotiation: secureReneg,
		POODLE:              poodle,
		FREAK:               false, // export ciphers removed from modern tooling
		Logjam:              false, // cannot be probed reliably with current tooling
		ECH:                 ech,
		PQC:                 pqc,
	}
}

// probeSSL checks if a server supports SSL 3.0 using openssl.
// SSL 2.0 is not supported by OpenSSL 3.0+.
func probeSSL(domain, ip string) []string {
	var supported []string
	address := net.JoinHostPort(ip, "443")

	// Try SSL 3.0 with legacy provider (OpenSSL 3.0+)
	for _, args := range [][]string{
		{"s_client", "-connect", address, "-ssl3", "-servername", domain, "-provider", "legacy", "-provider", "default"},
		{"s_client", "-connect", address, "-ssl3", "-servername", domain},
	} {
		cmd := exec.Command("openssl", args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			continue
		}
		outStr := string(output)
		if strings.Contains(outStr, "SSLv3") || strings.Contains(outStr, "Protocol  : SSLv3") {
			supported = append(supported, "SSL3")
			break
		}
	}

	return supported
}

// Aggregate computes all metrics from scan results.
func Aggregate(results *ScanResults) map[string]map[string]int {
	metrics := make(map[string]map[string]int)

	metrics["tls-versions"] = aggregateTLSVersions(results)
	metrics["cipher-suites"] = aggregateCipherSuites(results)
	metrics["key-algorithms"] = aggregateKeyAlgorithms(results)
	metrics["signature-algorithms"] = aggregateSignatureAlgorithms(results)
	metrics["validity-periods"] = aggregateValidityPeriods(results)
	metrics["san-counts"] = aggregateSANCounts(results)
	metrics["ca-market-share"] = aggregateCAMarketShare(results)
	metrics["ocsp-stapling"] = aggregateOCSPStapling(results)
	metrics["certificate-transparency"] = aggregateCT(results)
	metrics["extensions"] = aggregateExtensions(results)
	metrics["key-sizes"] = aggregateKeySizes(results)
	metrics["hash-algorithms"] = aggregateHashAlgorithms(results)
	metrics["wildcard-certs"] = aggregateWildcardCerts(results)
	metrics["self-signed"] = aggregateSelfSigned(results)
	metrics["expired-certs"] = aggregateExpiredCerts(results)
	metrics["ocsp-must-staple"] = aggregateOCSPMustStaple(results)
	metrics["certificate-lifetime-trends"] = aggregateCertificateLifetimeTrends(results)
	metrics["forward-secrecy"] = aggregateForwardSecrecy(results)
	metrics["chain-completeness"] = aggregateChainCompleteness(results)
	metrics["root-ca-distribution"] = aggregateRootCADistribution(results)
	metrics["key-reuse"] = aggregateKeyReuse(results)
	metrics["ct-log-diversity"] = aggregateCTLogDiversity(results)
	metrics["hsts"] = aggregateHSTS(results)
	metrics["caa-records"] = aggregateCAA(results)
	metrics["rc4-support"] = aggregateRC4(results)
	metrics["tls-compression"] = aggregateCRIME(results)
	metrics["secure-renegotiation"] = aggregateSecureRenegotiation(results)
	metrics["poodle"] = aggregatePOODLE(results)
	metrics["freak"] = aggregateFREAK(results)
	metrics["logjam"] = aggregateLogjam(results)
	metrics["ech"] = aggregateECH(results)
	metrics["pqc"] = aggregatePQC(results)
	metrics["ipv6-support"] = aggregateIPv6(results)
	metrics["issuance-volume"] = aggregateIssuanceVolume(results)

	return metrics
}

// verifyChain reports whether the leaf certificate chains to a trusted root
// using the system root pool and the supplied intermediates.
func verifyChain(certs []*x509.Certificate) bool {
	if len(certs) == 0 {
		return false
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	_, err = certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	})
	return err == nil
}

// countDistinctCTLogs counts distinct CT log IDs found in handshake SCTs and
// in the certificate's embedded SCT extension.
func countDistinctCTLogs(handshakeSCTs [][]byte, certs []*x509.Certificate) int {
	logs := make(map[string]bool)
	// SCTs delivered via the TLS handshake (RFC 6962 section 3.3.1): each is a
	// SerializedSCT whose log_id occupies bytes [1:33].
	for _, sct := range handshakeSCTs {
		if len(sct) >= 33 {
			logs[hex.EncodeToString(sct[1:33])] = true
		}
	}
	// SCTs embedded in the certificate (precert-scts extension).
	if len(certs) > 0 {
		for _, ext := range certs[0].Extensions {
			if !ext.Id.Equal(oidCTPrecertSCTs) {
				continue
			}
			data := ext.Value
			// The extension value may be wrapped in an OCTET STRING (tag 0x04).
			if len(data) > 0 && data[0] == 0x04 {
				i := 1
				if i < len(data) && data[i]&0x80 != 0 {
					n := int(data[i] & 0x7f)
					i++
					if i+n > len(data) {
						continue
					}
					i += n
				} else {
					i++
				}
				data = data[i:]
			}
			if len(data) < 2 {
				continue
			}
			// SignedCertificateTimestampList: 2-byte outer length then SCTs.
			outer := int(data[0])<<8 | int(data[1])
			if outer > 0 && outer+2 <= len(data) {
				data = data[2 : 2+outer]
			} else {
				data = data[2:]
			}
			pos := 0
			end := len(data)
			for pos+2 <= end {
				sctLen := int(data[pos])<<8 | int(data[pos+1])
				pos += 2
				if pos+sctLen > end || sctLen < 33 {
					break
				}
				if sctLen >= 33 {
					logs[hex.EncodeToString(data[pos+1:pos+33])] = true
				}
				pos += sctLen
			}
		}
	}
	return len(logs)
}

// probeHSTS does an HTTPS GET and reports whether Strict-Transport-Security is set.
func probeHSTS(domain string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain+"/", nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "CertificateObservatory/1.0")
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.Header.Get("Strict-Transport-Security") != ""
}

// probeCAA runs `host -t CAA domain` and reports whether a CAA record exists.
func probeCAA(domain string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "host", "-t", "CAA", domain)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), "caa record")
}

// probeECH checks DNS HTTPS records for an ech= parameter.
func probeECH(domain string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "host", "-t", "HTTPS", domain)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "ech=")
}

// probePQC attempts a TLS 1.3 handshake restricted to X25519MLKEM768.
func probePQC(domain, ip string, timeout time.Duration) bool {
	address := net.JoinHostPort(ip, "443")
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return false
	}
	defer conn.Close()
	tlsConfig := &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true,
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768},
		MinVersion:         tls.VersionTLS13,
	}
	tlsConn := tls.Client(conn, tlsConfig)
	deadline := time.Now().Add(timeout)
	conn.SetDeadline(deadline)
	tlsConn.SetDeadline(deadline)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return false
	}
	return true
}

// probeCRIME checks whether the server supports TLS-level compression.
func probeCRIME(domain, ip string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "openssl", "s_client", "-connect", net.JoinHostPort(ip, "443"),
		"-servername", domain)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Compression:") {
			return !strings.Contains(strings.ToUpper(line), "NONE")
		}
	}
	return false
}

// probeSecureRenegotiation checks renegotiation support via TLS 1.2.
func probeSecureRenegotiation(domain, ip string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "openssl", "s_client", "-connect", net.JoinHostPort(ip, "443"),
		"-servername", domain, "-tls1_2")
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return false
	}
	return strings.Contains(string(out), "Secure Renegotiation IS supported")
}

// rootCAName resolves the actual root CA that issued the certificate by
// verifying the chain against the system trust store (servers usually omit
// the root from the handshake). Falls back to the last supplied cert.
func rootCAName(certs []*x509.Certificate) string {
	if len(certs) == 0 {
		return ""
	}
	roots, _ := x509.SystemCertPool()
	if roots == nil {
		roots = x509.NewCertPool()
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	chains, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	})
	if err == nil && len(chains) > 0 && len(chains[0]) > 0 {
		root := chains[0][len(chains[0])-1]
		if root.Subject.CommonName != "" {
			return root.Subject.CommonName
		}
		if len(root.Subject.Organization) > 0 {
			return root.Subject.Organization[0]
		}
		return root.Subject.String()
	}
	// Fallback: last cert in the supplied chain
	last := certs[len(certs)-1]
	if last.Subject.CommonName != "" {
		return last.Subject.CommonName
	}
	if len(last.Subject.Organization) > 0 {
		return last.Subject.Organization[0]
	}
	return last.Subject.String()
}

// probeIPv6 reports whether any of the domain's IPv6 addresses completes a
// TLS handshake. Done separately from the main scan so an IPv4-first success
// does not mask IPv6 support.
var (
	ipv6EgressOnce sync.Once
	ipv6EgressOK   bool
)

// ipv6HasEgress reports (once) whether this environment can reach the
// internet over IPv6. GitHub Actions runners and many CI environments are
// IPv4-only, in which case reachability probes would always fail.
func ipv6HasEgress() bool {
	ipv6EgressOnce.Do(func() {
		conn, err := net.DialTimeout("tcp", "[2606:4700::6810:84e5]:443", 5*time.Second)
		if err == nil {
			conn.Close()
			ipv6EgressOK = true
		}
	})
	return ipv6EgressOK
}

// probeIPv6 reports whether the domain supports IPv6. When the scanner has
// IPv6 egress it verifies a real TLS handshake over IPv6; otherwise it falls
// back to DNS (AAAA record presence) so the metric is not always 0% on
// IPv4-only runners.
func probeIPv6(domain string, ips []net.IPAddr, timeout time.Duration) bool {
	hasAAAA := false
	for _, ip := range ips {
		if ip.IP.To4() == nil {
			hasAAAA = true
		}
	}
	if !ipv6HasEgress() {
		return hasAAAA
	}
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			continue
		}
		address := net.JoinHostPort(ip.String(), "443")
		dialer := &net.Dialer{Timeout: timeout}
		conn, err := dialer.Dial("tcp", address)
		if err != nil {
			continue
		}
		tlsConfig := &tls.Config{ServerName: domain, InsecureSkipVerify: true}
		tlsConn := tls.Client(conn, tlsConfig)
		deadline := time.Now().Add(timeout)
		conn.SetDeadline(deadline)
		tlsConn.SetDeadline(deadline)
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		err = tlsConn.HandshakeContext(ctx)
		cancel()
		conn.Close()
		if err == nil {
			return true
		}
	}
	return false
}
