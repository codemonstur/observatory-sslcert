package tranco

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"
)

const defaultTrancoURL = "https://tranco-list.eu/top-1m.csv.zip"

// FetchTop1M downloads and parses the Tranco Top 1M CSV.
func FetchTop1M(url string) ([]string, error) {
	if url == "" {
		url = defaultTrancoURL
	}

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Tranco provides a zip file containing top-1m.csv.
	// Buffer in memory: zip.NewReader needs an io.ReaderAt, which the
	// streaming resp.Body does not implement.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		// Maybe it's not zipped? Try reading as plain CSV
		return parseCSV(bytes.NewReader(body))
	}

	for _, f := range zipReader.File {
		if strings.HasSuffix(f.Name, ".csv") {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("open zip entry: %w", err)
			}
			defer rc.Close()
			return parseCSV(rc)
		}
	}

	return nil, fmt.Errorf("no CSV file found in zip")
}

func parseCSV(r io.Reader) ([]string, error) {
	reader := csv.NewReader(bufio.NewReader(r))
	reader.FieldsPerRecord = -1 // Variable fields

	var domains []string
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("csv parse: %w", err)
		}
		if len(record) >= 2 {
			domain := strings.TrimSpace(strings.ToLower(record[1]))
			if domain != "" && !strings.Contains(domain, " ") {
				domains = append(domains, domain)
			}
		}
	}
	return domains, nil
}

// RandomSample returns a random sample of n domains using Fisher-Yates shuffle.
func RandomSample(domains []string, n int, seed int64) []string {
	if n >= len(domains) {
		return domains
	}

	r := rand.New(rand.NewSource(seed))
	// Partial Fisher-Yates: only shuffle first n elements
	for i := 0; i < n; i++ {
		j := i + r.Intn(len(domains)-i)
		domains[i], domains[j] = domains[j], domains[i]
	}
	return domains[:n]
}

// FetchTop1MCached downloads Tranco list with caching to avoid re-download in tests.
func FetchTop1MCached(url, cachePath string, maxAge time.Duration) ([]string, error) {
	// Check cache
	if info, err := os.Stat(cachePath); err == nil {
		if time.Since(info.ModTime()) < maxAge {
			f, err := os.Open(cachePath)
			if err == nil {
				defer f.Close()
				return parseCSV(f)
			}
		}
	}

	domains, err := FetchTop1M(url)
	if err != nil {
		return nil, err
	}

	// Write cache
	if f, err := os.Create(cachePath); err == nil {
		defer f.Close()
		w := csv.NewWriter(f)
		for _, d := range domains {
			w.Write([]string{"", d}) // rank, domain
		}
		w.Flush()
	}
	return domains, nil
}
