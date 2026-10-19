package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Snapshot represents a single measurement at a point in time.
type Snapshot struct {
	Timestamp  string                 `json:"timestamp"`
	SampleSize int                    `json:"sample_size"`
	Data       map[string]interface{} `json:"data"`
}

// MetricHistory is a time-series of snapshots for one metric.
type MetricHistory []Snapshot

// LoadHistory reads all JSON files from the output directory.
// Missing files/directories are fine (a metric just starts fresh).
// A file that is empty or corrupt is skipped with a warning rather than
// failing the whole load, so one bad file cannot wipe the other metrics'
// history.
func LoadHistory(outputDir string) (map[string][]Snapshot, []string, error) {
	history := make(map[string][]Snapshot)
	var warnings []string

	entries, err := os.ReadDir(outputDir)
	if err != nil {
		if os.IsNotExist(err) {
			return history, warnings, nil
		}
		return nil, warnings, err
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		metricName := entry.Name()[:len(entry.Name())-5] // strip .json
		path := filepath.Join(outputDir, entry.Name())

		data, err := os.ReadFile(path)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("skip %s: %v", path, err))
			continue
		}

		var snapshots []Snapshot
		if len(data) > 0 {
			if err := json.Unmarshal(data, &snapshots); err != nil {
				warnings = append(warnings, fmt.Sprintf("skip %s: %v", path, err))
				continue
			}
		}
		history[metricName] = snapshots
	}

	return history, warnings, nil
}

// WriteHistory writes all metrics to JSON files in the output directory.
func WriteHistory(outputDir string, history map[string][]Snapshot) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	for metricName, snapshots := range history {
		// Sort by timestamp
		sort.Slice(snapshots, func(i, j int) bool {
			return snapshots[i].Timestamp < snapshots[j].Timestamp
		})

		path := filepath.Join(outputDir, metricName+".json")
		data, err := json.MarshalIndent(snapshots, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal %s: %w", metricName, err)
		}

		if err := os.WriteFile(path, data, 0644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}

	return nil
}

// LatestSnapshot returns the most recent snapshot for a metric.
func LatestSnapshot(history []Snapshot) *Snapshot {
	if len(history) == 0 {
		return nil
	}
	return &history[len(history)-1]
}

// GetTimeSeries extracts a time series for a specific key within the metric data.
func GetTimeSeries(history []Snapshot, key string) ([]string, []float64) {
	var timestamps []string
	var values []float64

	for _, snap := range history {
		if v, ok := snap.Data[key]; ok {
			timestamps = append(timestamps, snap.Timestamp)
			switch val := v.(type) {
			case float64:
				values = append(values, val)
			case int:
				values = append(values, float64(val))
			case int64:
				values = append(values, float64(val))
			default:
				values = append(values, 0)
			}
		}
	}
	return timestamps, values
}

// GetLatestDistribution returns the latest distribution map for a metric.
func GetLatestDistribution(history []Snapshot) map[string]int {
	snap := LatestSnapshot(history)
	if snap == nil {
		return nil
	}

	dist := make(map[string]int)
	for k, v := range snap.Data {
		switch val := v.(type) {
		case float64:
			dist[k] = int(val)
		case int:
			dist[k] = val
		case int64:
			dist[k] = int(val)
		}
	}
	return dist
}

// FormatTimestamp converts RFC3339 to a shorter display format.
func FormatTimestamp(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	return t.Format("2006-01-02")
}
