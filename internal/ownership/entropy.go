package ownership

import (
	"math"
	"sort"
)

// Shannon computes the Shannon entropy of a frequency distribution.
// counts is a map from author identifier to commit count.
// Returns 0 for empty or single-author inputs.
// The result is in bits (log base 2).
func Shannon(counts map[string]int) float64 {
	total := 0
	for _, c := range counts {
		total += c
	}
	if total == 0 {
		return 0
	}

	var entropy float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(total)
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// NormalizedEntropy returns entropy normalized to [0, 1] given the number of distinct authors.
// A single author yields 0; equal contribution across all authors yields 1.
func NormalizedEntropy(counts map[string]int) float64 {
	n := len(counts)
	if n <= 1 {
		return 0
	}
	raw := Shannon(counts)
	max := math.Log2(float64(n))
	if max == 0 {
		return 0
	}
	return raw / max
}

// DominantOwner returns the author with the most commits, along with their share [0,1].
// Returns ("", 0) if counts is empty.
func DominantOwner(counts map[string]int) (author string, share float64) {
	total := 0
	best := 0
	authors := make([]string, 0, len(counts))
	for a := range counts {
		authors = append(authors, a)
	}
	sort.Strings(authors)
	for _, a := range authors {
		c := counts[a]
		total += c
		if c > best {
			best = c
			author = a
		}
	}
	if total == 0 {
		return "", 0
	}
	return author, float64(best) / float64(total)
}
