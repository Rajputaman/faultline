package git

import (
	"reflect"
	"testing"
)

func TestParseNumstatChurn(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{
			name: "empty output",
			in:   "",
			want: 0,
		},
		{
			name: "added and deleted lines",
			in:   "10\t2\tinternal/app/app.go\n3\t7\tinternal/app/app_test.go\n",
			want: 22,
		},
		{
			name: "binary files are skipped",
			in:   "-\t-\tassets/logo.png\n5\t1\tinternal/app/app.go\n",
			want: 6,
		},
		{
			name: "malformed numeric fields are skipped",
			in:   "bad\t2\tinternal/app/app.go\n1\tbad\tinternal/app/app.go\n8\t2\tinternal/app/ok.go\n",
			want: 10,
		},
		{
			name: "extra whitespace and spaces in path",
			in:   "  4   6   docs/file with spaces.md  \n\n",
			want: 10,
		},
		{
			name: "short lines are skipped",
			in:   "4\t6\n2\t3\tinternal/app/app.go\n",
			want: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseNumstatChurn(tt.in); got != tt.want {
				t.Fatalf("parseNumstatChurn() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestParseAuthorCounts(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want map[string]int
	}{
		{
			name: "empty output",
			in:   "",
			want: map[string]int{},
		},
		{
			name: "counts repeated authors",
			in:   "alice@example.com\nbob@example.com\nalice@example.com\n",
			want: map[string]int{"alice@example.com": 2, "bob@example.com": 1},
		},
		{
			name: "trims whitespace and ignores blank lines",
			in:   " alice@example.com \n\n\tbob@example.com\t\n",
			want: map[string]int{"alice@example.com": 1, "bob@example.com": 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseAuthorCounts(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseAuthorCounts() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
