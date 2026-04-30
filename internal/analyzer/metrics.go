package analyzer

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Metrics captures simple source metrics for one package directory.
type Metrics struct {
	LOC                int
	TestLOC            int
	GeneratedLOC       int
	FileCount          int
	GeneratedFileCount int
	Errors             []string
}

type MetricOptions struct {
	IncludeGenerated bool
}

// CollectMetrics counts Go files and non-blank, non-comment lines in a package
// directory. It does not recurse into subdirectories because Go packages are
// directory-scoped.
func CollectMetrics(dir string, opts MetricOptions) (Metrics, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return Metrics{}, fmt.Errorf("read package dir %s: %w", dir, err)
	}
	var metrics Metrics
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			metrics.Errors = append(metrics.Errors, fmt.Sprintf("read %s: %v", path, err))
			continue
		}
		metrics.FileCount++
		generated := IsGeneratedFile(name, data)
		if generated {
			metrics.GeneratedFileCount++
		}
		loc := countLOC(data)
		switch {
		case strings.HasSuffix(name, "_test.go"):
			metrics.TestLOC += loc
		case generated:
			metrics.GeneratedLOC += loc
			if opts.IncludeGenerated {
				metrics.LOC += loc
			}
		default:
			metrics.LOC += loc
		}
	}
	return metrics, nil
}

// IsGeneratedFile detects common generated-code markers and file names.
func IsGeneratedFile(name string, data []byte) bool {
	base := filepath.Base(name)
	if strings.HasSuffix(base, ".pb.go") ||
		strings.HasSuffix(base, "_generated.go") ||
		strings.HasPrefix(base, "mock_") ||
		(strings.HasPrefix(base, "zz_generated") && strings.HasSuffix(base, ".go")) {
		return true
	}

	head := data
	if len(head) > 4096 {
		head = head[:4096]
	}
	if idx := bytes.Index(head, []byte("package ")); idx >= 0 {
		head = head[:idx]
	}
	head = bytes.ToLower(head)
	return bytes.Contains(head, []byte("code generated")) ||
		bytes.Contains(head, []byte("do not edit"))
}

func countLOC(data []byte) int {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	inBlock := false
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if inBlock {
			if idx := strings.Index(line, "*/"); idx >= 0 {
				inBlock = false
				line = strings.TrimSpace(line[idx+2:])
				if line == "" {
					continue
				}
			} else {
				continue
			}
		}
		if strings.HasPrefix(line, "/*") {
			if idx := strings.Index(line, "*/"); idx >= 0 {
				line = strings.TrimSpace(line[idx+2:])
				if line == "" {
					continue
				}
			} else {
				inBlock = true
				continue
			}
		}
		if strings.HasPrefix(line, "//") {
			continue
		}
		count++
	}
	return count
}
