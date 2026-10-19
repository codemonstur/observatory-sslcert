# TODO: Harder Metrics for Certificate Observatory

These metrics require additional probing, external data sources, or significant scanner changes.

## Security Posture

### Forward Secrecy Support
- **Description**: Whether servers support ECDHE/DHE key exchange (Perfect Forward Secrecy)
- **Implementation**: Check if the negotiated cipher suite uses ECDHE or DHE key exchange. Already have cipher suite data; need to classify each cipher suite.
- **Effort**: Medium (classify existing cipher suite data)

### HSTS Support
- **Description**: HTTP Strict Transport Security header presence and max-age
- **Implementation**: Requires HTTP GET request to check response headers (not just TLS handshake). Need to add HTTP client to scanner.
- **Effort**: Medium

### Certificate Chain Completeness
- **Description**: Whether the full certificate chain (intermediates) is served by the server
- **Implementation**: Check if `len(r.Certificates) >= 2` and verify chain builds to a trusted root. Already partially tracked (CA market share uses `Certificates[1]`).
- **Effort**: Medium

### CAA Records
- **Description**: Certificate Authority Authorization DNS records
- **Implementation**: DNS TXT lookup for `_caa` records. Need to add DNS query to scanner.
- **Effort**: Medium

## Vulnerability Tracking

### RC4 Support
- **Description**: Servers still accepting RC4 cipher (deprecated, insecure)
- **Implementation**: Check if any RC4 cipher suite is in the supported list. Need TLS handshake with specific cipher suites.
- **Effort**: Medium

### TLS Compression (CRIME)
- **Description**: TLS compression support (CRIME vulnerability)
- **Implementation**: Check if server supports DEFLATE compression. Need specific TLS probe.
- **Effort**: Hard

### Secure Renegotiation
- **Description**: Secure vs insecure TLS renegotiation
- **Implementation**: Requires TLS renegotiation probe. Complex TLS-level testing.
- **Effort**: Hard

### POODLE / FREAK / Logjam
- **Description**: Vulnerability to specific TLS attacks
- **Implementation**: Requires specific protocol/cipher probes for each vulnerability.
- **Effort**: Hard

## Modern Standards

### Encrypted Client Hello (ECH)
- **Description**: Privacy-preserving SNI encryption support
- **Implementation**: Check for ECH extension in TLS handshake. Go's crypto/tls may expose this in newer versions.
- **Effort**: Medium (depends on Go version)

### Post-Quantum Cryptography (PQC)
- **Description**: Kyber/ML-KEM key exchange support
- **Implementation**: Requires TLS 1.3 with hybrid key exchange. Go 1.24+ may support this.
- **Effort**: Hard (depends on Go/crypto/tls support)

### OCSP Must-Staple (standalone metric)
- **Description**: Already tracked in extensions metric, but could be a dedicated chart
- **Implementation**: Extract from existing extensions data. Just needs new aggregate function and chart entry.
- **Effort**: Easy

## CA Ecosystem

### Root CA Distribution
- **Description**: Which root CAs are most used (vs intermediate CAs)
- **Implementation**: Extract root CA from certificate chain (last cert in chain). Already have chain data.
- **Effort**: Easy-Medium

### CT Log Diversity
- **Description**: Number of distinct Certificate Transparency logs used
- **Implementation**: Extract SCT log IDs from certificate extensions. Need CT log list for mapping.
- **Effort**: Medium

### Certificate Issuance Volume
- **Description**: New certificates issued per week/month
- **Implementation**: Requires crt.sh or CT log API queries, not per-domain scanning.
- **Effort**: Hard (different data source)

## Certificate Properties

### Certificate Key Reuse
- **Description**: Same public key used across multiple domains
- **Implementation**: Hash public keys and track duplicates across the scan. Need cross-domain analysis.
- **Effort**: Medium

### Certificate Lifetime Trends
- **Description**: Track 90-day vs 1-year vs multi-year certificate trends over time
- **Implementation**: Already have validity-periods data; could add specific buckets for 90-day, 398-day (CA/Browser Forum max), etc.
- **Effort**: Easy

## Infrastructure

### Multiple Scan Locations
- **Description**: Scan from different geographic locations to detect CDN/regional differences
- **Implementation**: Run scanner from multiple GitHub Actions runners (different regions).
- **Effort**: Medium

### IPv6 Support
- **Description**: Scan domains over IPv6 in addition to IPv4
- **Implementation**: Add IPv6 resolution and scanning to scanner.
- **Effort**: Medium
