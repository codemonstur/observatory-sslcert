# Certificate Observatory

A static-site certificate observatory that scans a random sample of the Tranco Top 1M domains weekly via GitHub Actions, stores results as JSON, and visualizes trends in a browser dashboard.

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  GitHub Action  │────▶│  Scanner (Go)    │────▶│  JSON Files     │
│  (weekly cron)  │     │  - Tranco list   │     │  /data/         │
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
| `san-counts.json` | Number of SAN entries per cert |
| `ca-market-share.json` | Issuer CA distribution |
| `ocsp-stapling.json` | OCSP stapling support |
| `certificate-transparency.json` | SCT presence |
| `extensions.json` | Key usage, EKU, basic constraints, etc. |
| `key-sizes.json` | RSA/ECDSA key size distribution |
| `hash-algorithms.json` | SHA-1, SHA-256, SHA-384, SHA-512 usage |
| `wildcard-certs.json` | Wildcard vs non-wildcard certificates |
| `self-signed.json` | Self-signed vs CA-signed certificates |
| `expired-certs.json` | Expired certificates still in use |

## Local Development

```bash
# Build scanner
cd scanner && go build -o ../bin/scanner .

# Run scanner locally (uses cached Tranco list)
./bin/scanner -sample 100 -output ../data

# Serve static site locally
cd site && python3 -m http.server 8080
# Open http://localhost:8080
```

## Deployment

1. Push to GitHub
2. Enable GitHub Pages (source: `/site` folder)
3. GitHub Action runs weekly, commits updated JSON to `data/`
4. Site auto-updates on push

## Directory Structure

```
observatory-certificates/
├── .github/workflows/scan.yml    # GitHub Action workflow
├── scanner/                      # Go TLS scanner
│   ├── main.go
│   ├── scan.go
│   ├── parse.go
│   ├── tranco.go
│   └── go.mod
├── site/                         # Static website
│   ├── index.html
│   ├── charts.js
│   ├── style.css
│   └── lib/                      # Chart library (uPlot)
└── data/                         # JSON output (committed by Action)
    ├── tls-versions.json
    ├── cipher-suites.json
    └── ...
```