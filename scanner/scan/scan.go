package scan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
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
	Domain       string
	Success      bool
	Error        string
	Handshake    *HandshakeInfo
	Certificates []*x509.Certificate
	OCSPStapled  bool
}

type HandshakeInfo struct {
	Version            uint16
	CipherSuite        uint16
	ServerName         string
	Resumed            bool
	OCSPStapled        bool
	SCTs               [][]byte
	SupportedVersions  []uint16
	SupportedGroups    []tls.CurveID
	SupportedSigAlgs   []tls.SignatureScheme
	SSLVersions        []string // SSL 3.0 (detected via openssl)
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
	verifiedChains := state.VerifiedChains

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

	// Build handshake info
	handshake := &HandshakeInfo{
		Version:           state.Version,
		CipherSuite:       state.CipherSuite,
		ServerName:        state.ServerName,
		Resumed:           state.DidResume,
		OCSPStapled:       ocspStapled,
		SCTs:              scts,
		SupportedVersions: state.SupportedVersions,
		SupportedGroups:   state.SupportedGroups,
		SupportedSigAlgs:  state.SupportedSignatureAlgorithms,
		SSLVersions:       sslVersions,
	}

	return Result{
		Domain:       domain,
		Success:      true,
		Handshake:    handshake,
		Certificates: certs,
		OCSPStapled:  ocspStapled,
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
func Aggregate(results *ScanResults) map[string]interface{} {
	metrics := make(map[string]interface{})

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

	return metrics
}