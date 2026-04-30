package ownership

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/faultline-go/faultline/internal/policy"
)

func TestResolveOwnershipPrecedenceAndFallbacks(t *testing.T) {
	dir := t.TempDir()
	pkgDir := filepath.Join(dir, "service-a", "internal", "api")
	if err := os.MkdirAll(pkgDir, 0755); err != nil {
		t.Fatal(err)
	}
	codeowners := &Codeowners{
		Path: filepath.Join(dir, "CODEOWNERS"),
		Rules: []Rule{
			{Pattern: "/service-a/", Owners: []string{"@codeowners-team"}},
		},
	}
	cfg := policy.OwnersConfig{
		Aliases: map[string][]string{
			"@payments-platform": {"alice@example.com", "@github-team/payments"},
		},
		Modules: map[string]policy.ModuleOwnerConfig{
			"example.com/service-a": {Owner: "@service-a-team"},
		},
	}

	tests := []struct {
		name       string
		cfg        policy.OwnersConfig
		codeowners *Codeowners
		authors    map[string]int
		wantOwner  string
		wantSource string
	}{
		{
			name:       "module owner wins",
			cfg:        cfg,
			codeowners: codeowners,
			authors:    map[string]int{"alice@example.com": 3},
			wantOwner:  "@service-a-team",
			wantSource: SourceModuleOwner,
		},
		{
			name: "CODEOWNERS fallback",
			cfg: policy.OwnersConfig{
				Aliases: cfg.Aliases,
			},
			codeowners: codeowners,
			authors:    map[string]int{"alice@example.com": 3},
			wantOwner:  "@codeowners-team",
			wantSource: SourceCodeowners,
		},
		{
			name: "dominant author alias fallback",
			cfg: policy.OwnersConfig{
				Aliases: cfg.Aliases,
			},
			authors:    map[string]int{"alice@example.com": 3, "zoe@example.com": 1},
			wantOwner:  "@payments-platform",
			wantSource: SourceGitAlias,
		},
		{
			name:       "dominant author raw fallback",
			authors:    map[string]int{"zoe@example.com": 2},
			wantOwner:  "zoe@example.com",
			wantSource: SourceGitAuthor,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Resolve(ResolveInput{
				Config:         tt.cfg,
				ModulePath:     "example.com/service-a",
				ModuleRoot:     "service-a",
				CodeownersRoot: dir,
				PackageDir:     pkgDir,
				Codeowners:     tt.codeowners,
				AuthorCounts:   tt.authors,
			})
			if got.Owner != tt.wantOwner || got.Source != tt.wantSource {
				t.Fatalf("owner/source = %q/%q, want %q/%q", got.Owner, got.Source, tt.wantOwner, tt.wantSource)
			}
			if len(got.Candidates) == 0 {
				t.Fatalf("expected candidate owners")
			}
			if len(got.Evidence) == 0 {
				t.Fatalf("expected ownership evidence")
			}
		})
	}
}

func TestResolveAliasDeterministic(t *testing.T) {
	aliases := map[string][]string{
		"@z-team": {"alice@example.com"},
		"@a-team": {"alice@example.com"},
	}
	owner, ok := ResolveAlias(aliases, "ALICE@example.com")
	if !ok {
		t.Fatal("expected alias match")
	}
	if owner != "@a-team" {
		t.Fatalf("owner = %q, want deterministic first alias", owner)
	}
}

func TestResolveModuleOwnerMissing(t *testing.T) {
	got := Resolve(ResolveInput{
		Config:      policy.OwnersConfig{},
		ModulePath:  "example.com/shared",
		ModuleRoot:  "shared",
		MultiModule: true,
	})
	if !got.ModuleOwnerMissing {
		t.Fatalf("expected missing module owner diagnostic")
	}
	if got.Owner != "" || got.Source != SourceUnknown {
		t.Fatalf("owner/source = %q/%q, want unknown", got.Owner, got.Source)
	}
}

func TestResolveEvidenceOrderingDeterministic(t *testing.T) {
	cfg := policy.OwnersConfig{
		Aliases: map[string][]string{
			"@z-team": {"z@example.com"},
			"@a-team": {"a@example.com"},
		},
		Modules: map[string]policy.ModuleOwnerConfig{
			"example.com/app": {Owner: "@app-team"},
		},
	}
	input := ResolveInput{
		Config:     cfg,
		ModulePath: "example.com/app",
		ModuleRoot: "app",
		AuthorCounts: map[string]int{
			"z@example.com": 1,
			"a@example.com": 1,
		},
	}
	first := Resolve(input)
	second := Resolve(input)
	if !reflect.DeepEqual(first.Candidates, second.Candidates) {
		t.Fatalf("candidates are not deterministic:\n%+v\n%+v", first.Candidates, second.Candidates)
	}
	if !reflect.DeepEqual(first.Evidence, second.Evidence) {
		t.Fatalf("evidence is not deterministic:\n%+v\n%+v", first.Evidence, second.Evidence)
	}
}
