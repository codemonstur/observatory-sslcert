package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"observatory-sslcert/scanner/output"
	"observatory-sslcert/scanner/scan"
	"observatory-sslcert/scanner/tranco"
)

func main() {
	sampleSize := flag.Int("sample", 2500, "Number of domains to scan")
	outputDir := flag.String("output", "docs/data", "Output directory for JSON files")
	timeoutSec := flag.Int("timeout", 10, "Connection timeout in seconds")
	concurrency := flag.Int("concurrency", 50, "Max concurrent connections")
	userAgent := flag.String("user-agent", "CertificateObservatory/1.0", "User agent string")
	trancoURL := flag.String("tranco-url", "https://tranco-list.eu/top-1m.csv.zip", "Tranco list URL")
	seed := flag.Int64("seed", 0, "Random seed (0 = current time)")
	flag.Parse()

	if *sampleSize <= 0 {
		log.Fatal("-sample must be positive")
	}
	if *concurrency <= 0 {
		log.Fatal("-concurrency must be positive")
	}
	if *timeoutSec <= 0 {
		log.Fatal("-timeout must be positive")
	}

	// Seed random for reproducible sampling
	if *seed == 0 {
		*seed = time.Now().UnixNano()
	}

	// Download Tranco list
	log.Printf("Downloading Tranco list from %s...", *trancoURL)
	domains, err := tranco.FetchTop1M(*trancoURL)
	if err != nil {
		log.Fatalf("Failed to fetch Tranco list: %v", err)
	}
	log.Printf("Loaded %d domains from Tranco list", len(domains))

	// Random sample
	sampled := tranco.RandomSample(domains, *sampleSize, *seed)
	log.Printf("Selected %d random domains (seed=%d)", len(sampled), *seed)

	// Scan
	scanner := scan.NewScanner(scan.Config{
		Timeout:     time.Duration(*timeoutSec) * time.Second,
		Concurrency: *concurrency,
		UserAgent:   *userAgent,
	})

	log.Printf("Starting scan with %d workers...", *concurrency)
	results := scanner.Scan(sampled)
	log.Printf("Scan complete: %d successful, %d failed", results.SuccessCount, results.FailCount)

	// Aggregate metrics
	metrics := scan.Aggregate(results)

	// Load existing history and append
	log.Printf("Loading existing history from %s...", *outputDir)
	history, warnings, err := output.LoadHistory(*outputDir)
	if err != nil {
		log.Printf("Warning: could not load history: %v", err)
		history = make(map[string][]output.Snapshot)
	}
	for _, w := range warnings {
		log.Printf("Warning: %s", w)
	}

	// Append new snapshot
	timestamp := time.Now().UTC().Format(time.RFC3339)
	for metricName, metricData := range metrics {
		data := make(map[string]interface{}, len(metricData))
		for k, v := range metricData {
			data[k] = v
		}
		snapshot := output.Snapshot{
			Timestamp:  timestamp,
			SampleSize: results.SuccessCount,
			Data:       data,
		}
		history[metricName] = append(history[metricName], snapshot)
	}

	// Write updated history
	log.Printf("Writing updated JSON files to %s...", *outputDir)
	if err := output.WriteHistory(*outputDir, history); err != nil {
		log.Fatalf("Failed to write output: %v", err)
	}

	// Print summary
	fmt.Println("\n=== Scan Summary ===")
	fmt.Printf("Timestamp:     %s\n", timestamp)
	fmt.Printf("Domains tried: %d\n", len(sampled))
	fmt.Printf("Successful:    %d\n", results.SuccessCount)
	fmt.Printf("Failed:        %d\n", results.FailCount)
	fmt.Printf("Metrics updated: %d\n", len(metrics))
	for name := range metrics {
		fmt.Printf("  - %s\n", name)
	}
}
