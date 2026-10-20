# Certificate Observatory

A static-site certificate observatory that scans a random sample of the Tranco Top 1M domains weekly via GitHub Actions, stores results as JSON, and visualizes trends in a browser dashboard.

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  GitHub Action  │────▶│  Scanner (Go)    │────▶│  JSON Files     │
│  (weekly cron)  │     │  - Tranco list   │     │  docs/data/     │
└─────────────────┘     │  - 2500 random   │     │  - tls-versions │
                        │  - TLS handshake │     │  - cipher-suites│
                        │  - X.509 parse   │     │  - key-algos    │
                        └──────────────────┘     │  - ...          │
                                                 └────────┬────────┘
                                                          │
                        ┌──────────────────┐              │
                        │  Static Site     │◀─────────────┘
                        │  (GitHub Pages)  │
                        │  - index.html    │
                        │  - charts.js     │
                        │  - loads JSON    │
                        └──────────────────┘
```

## Data Collection

- **Source**: Tranco Top 1M list (downloaded fresh each run)
- **Sample**: 2,500 randomly selected domains per run
- **Frequency**: Weekly (GitHub Actions cron: `0 0 * * 0` = Sundays)
- **Protocol**: TLS 1.2/1.3 handshake via Go's `crypto/tls`
- **Output**: One JSON file per metric, each containing an array of historical snapshots

## Metrics Tracked

| File | Description |
|------|-------------|
| `tls-versions.json` | SSL 3.0 and TLS 1.0, 1.1, 1.2, 1.3 support |
| `cipher-suites.json` | Cipher suite prevalence |
| `key-algorithms.json` | RSA, ECDSA, Ed25519 key types & sizes |
| `signature-algorithms.json` | SHA-1, SHA-256, SHA-384, etc. |
| `validity-periods.json` | Certificate lifetime distribution |
| `certificate-lifetime-trends.json` | Lifetime trends around 90/398/825-day policy thresholds |
| `san-counts.json` | Number of SAN entries per cert |
| `ca-market-share.json` | Issuer CA distribution |
| `ocsp-stapling.json` | OCSP stapling support |
| `ocsp-must-staple.json` | OCSP Must-Staple extension presence |
| `certificate-transparency.json` | SCT presence |
| `extensions.json` | Key usage, EKU, basic constraints, etc. |
| `key-sizes.json` | RSA/ECDSA key size distribution |
| `hash-algorithms.json` | SHA-1, SHA-256, SHA-384, SHA-512 usage |
| `wildcard-certs.json` | Wildcard vs non-wildcard certificates |
| `self-signed.json` | Self-signed vs CA-signed certificates |
| `expired-certs.json` | Expired certificates still in use |
| `forward-secrecy.json` | Forward secrecy (PFS) support |
| `chain-completeness.json` | Certificate chain completeness |
| `root-ca-distribution.json` | Root CA distribution |
| `key-reuse.json` | Certificate key reuse |
| `ct-log-diversity.json` | CT log diversity |
| `hsts.json` | HSTS support |
| `caa-records.json` | CAA records |
| `rc4-support.json` | RC4 support |
| `tls-compression.json` | TLS compression (CRIME) |
| `secure-renegotiation.json` | Secure renegotiation |
| `poodle.json` | POODLE (SSL 3.0) |
| `freak.json` | FREAK |
| `logjam.json` | Logjam |
| `ech.json` | Encrypted Client Hello |
| `pqc.json` | Post-quantum cryptography |
| `ipv6-support.json` | IPv6 support |
| `issuance-volume.json` | Certificate issuance volume |

## Local Development

```bash
# Build scanner
make build            # or: cd scanner && go build -o ../bin/scanner .

# Run scanner locally (writes to docs/data, the directory the site reads from)
make scan SAMPLE=100  # or: ./bin/scanner -sample 100

# Serve static site locally
make serve            # or: cd docs && python3 -m http.server 8080
# Open http://localhost:8080
```

## Deployment

1. Push to GitHub
2. Enable GitHub Pages: Settings → Pages → Source → **GitHub Actions** (not "Deploy from a branch")
3. The `pages.yml` workflow deploys the `docs/` folder on every push to `main`
4. The weekly `scan.yml` workflow commits updated JSON to `docs/data/`, which triggers a redeploy
5. Site is live at https://codemonstur.github.io/observatory-sslcert/

## Directory Structure

```
observatory-sslcert/
├── .github/workflows/scan.yml    # GitHub Action workflow
├── Makefile                      # Build/dev tasks (make help)
├── scanner/                      # Go TLS scanner
│   ├── main.go
│   ├── scan.go
│   ├── parse.go
│   ├── tranco.go
│   └── go.mod
├── docs/                         # Static website
│   ├── index.html
│   ├── charts.js
│   ├── style.css
│   ├── lib/                      # Chart library (uPlot)
│   └── data/                     # JSON output (committed by Action)
│       ├── tls-versions.json
│       ├── cipher-suites.json
│       └── ...
```