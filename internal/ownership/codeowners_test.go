package ownership

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOwnersForPath(t *testing.T) {
	content := `# comment
*                   @global
*.go                @go-team
/internal/          @internal-team
/internal/api/      @api-team
docs/               @docs-team
docs/private/       @private-docs @security
`
	dir := t.TempDir()
	p := filepath.Join(dir, "CODEOWNERS")
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	co, err := parseFile(p)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		path      string
		wantOwner string
	}{
		{"internal/api/handler.go", "@api-team"},
		{"internal/service/service.go", "@internal-team"},
		{"docs/architecture.md", "@docs-team"},
		{"docs/private/runbook.md", "@private-docs"},
		{"main.go", "@go-team"},
		{"LICENSE", "@global"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			owners := co.OwnersForPath(tt.path)
			if len(owners) == 0 {
				t.Fatalf("got no owners for %q, want %q", tt.path, tt.wantOwner)
			}
			if owners[0] != tt.wantOwner {
				t.Errorf("owner[0] = %q, want %q", owners[0], tt.wantOwner)
			}
			if tt.path == "docs/private/runbook.md" && len(owners) != 2 {
				t.Errorf("owners = %v, want multiple owners", owners)
			}
		})
	}
}

func TestCodeownersMatchMetadata(t *testing.T) {
	co := &Codeowners{
		Path: "CODEOWNERS",
		Rules: []Rule{
			{Pattern: "/pkg/", Owners: []string{"@pkg"}, Line: 1},
			{Pattern: "/pkg/api/", Owners: []string{"@api"}, Line: 2},
		},
	}
	match := co.MatchForPath("pkg/api/handler.go")
	if match.Line != 2 || match.Pattern != "/pkg/api/" || len(match.Owners) != 1 || match.Owners[0] != "@api" {
		t.Fatalf("match = %+v, want line 2 /pkg/api/ @api", match)
	}
	fileMatch := co.ResolveFileOwner("pkg/api/handler.go")
	if fileMatch.Line != match.Line || fileMatch.Pattern != match.Pattern {
		t.Fatalf("ResolveFileOwner = %+v, want %+v", fileMatch, match)
	}
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"*", "file.go", true},
		{"*", "dir/file.go", true},
		{"**", "a/b/c.go", true},
		{"*.go", "main.go", true},
		{"*.go", "main.js", false},
		{"/internal/", "internal/pkg/file.go", true},
		{"/internal/", "vendor/internal/file.go", false},
		{"docs/", "docs/a/b.md", true},
		{"docs/", "other/docs/b.md", true},
		{"*.pb.go", "pkg/api/service.pb.go", true},
		{"/pkg/*/api/", "pkg/payments/api/server.go", true},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.path, func(t *testing.T) {
			got := matchPattern(tt.pattern, tt.path)
			if got != tt.want {
				t.Errorf("matchPattern(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
			}
		})
	}
}

func TestLoadCodeowners_NotFound(t *testing.T) {
	dir := t.TempDir()
	co, err := LoadCodeowners(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if co != nil {
		t.Fatal("expected nil for missing CODEOWNERS")
	}
}

func TestLoadCodeowners_Locations(t *testing.T) {
	tests := []struct {
		name      string
		paths     []string
		wantPath  string
		wantOwner string
	}{
		{"root", []string{"CODEOWNERS"}, "CODEOWNERS", "@root"},
		{"github wins over root", []string{"CODEOWNERS", ".github/CODEOWNERS"}, ".github/CODEOWNERS", "@github"},
		{"root wins over docs", []string{"docs/CODEOWNERS", "CODEOWNERS"}, "CODEOWNERS", "@root"},
		{"docs fallback", []string{"docs/CODEOWNERS"}, "docs/CODEOWNERS", "@docs"},
	}
	ownersByPath := map[string]string{
		"CODEOWNERS":         "@root",
		".github/CODEOWNERS": "@github",
		"docs/CODEOWNERS":    "@docs",
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, path := range tt.paths {
				p := filepath.Join(dir, filepath.FromSlash(path))
				if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte("/pkg/ "+ownersByPath[path]+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			co, err := LoadCodeowners(dir)
			if err != nil {
				t.Fatal(err)
			}
			if co == nil {
				t.Fatal("expected CODEOWNERS")
			}
			rel, err := filepath.Rel(dir, co.Path)
			if err != nil {
				t.Fatal(err)
			}
			if filepath.ToSlash(rel) != tt.wantPath {
				t.Fatalf("path = %q, want %q", filepath.ToSlash(rel), tt.wantPath)
			}
			owners := co.OwnersForPath("pkg/file.go")
			if len(owners) != 1 || owners[0] != tt.wantOwner {
				t.Fatalf("owners = %v, want %s", owners, tt.wantOwner)
			}
		})
	}
}

func TestParseFileDiagnostics(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "CODEOWNERS")
	content := `pkg/no-owner/
!pkg/negated/ @team
pkg/[ab]/ @team
pkg/invalid-owner/ team
pkg/trailing\ @team
pkg/space\ dir/ @space-team
`
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	co, err := parseFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(co.Diagnostics) != 5 {
		t.Fatalf("diagnostics = %+v, want 5", co.Diagnostics)
	}
	match := co.MatchForPath("pkg/space dir/file.go")
	if len(match.Owners) != 1 || match.Owners[0] != "@space-team" {
		t.Fatalf("escaped space match = %+v", match)
	}
}

func TestOwnersForPackageMatchedRule(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "CODEOWNERS")
	if err := os.WriteFile(p, []byte(`/pkg/ @pkg
/pkg/api/ @api
`), 0600); err != nil {
		t.Fatal(err)
	}
	co, err := parseFile(p)
	if err != nil {
		t.Fatal(err)
	}
	match := co.MatchForPackage(dir, filepath.Join(dir, "pkg", "api"))
	if match.Line != 2 || match.Pattern != "/pkg/api/" || len(match.Owners) != 1 || match.Owners[0] != "@api" {
		t.Fatalf("match = %+v, want pkg api rule", match)
	}
}

func TestOwnersForPackage(t *testing.T) {
	dir := t.TempDir()
	content := `/pkg/mathy/ @math-team
/internal/store/ @platform-team
`
	p := filepath.Join(dir, "CODEOWNERS")
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	co, err := parseFile(p)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		pkgDir string
		want   string
	}{
		{filepath.Join(dir, "pkg", "mathy"), "@math-team"},
		{filepath.Join(dir, "internal", "store"), "@platform-team"},
		{filepath.Join(dir, "internal", "missing"), ""},
	}
	for _, tt := range tests {
		t.Run(tt.pkgDir, func(t *testing.T) {
			owners := co.OwnersForPackage(dir, tt.pkgDir)
			if tt.want == "" {
				if len(owners) != 0 {
					t.Fatalf("owners = %v, want none", owners)
				}
				return
			}
			if len(owners) == 0 || owners[0] != tt.want {
				t.Fatalf("owners = %v, want %s", owners, tt.want)
			}
		})
	}
}
