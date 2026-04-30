package module

import (
	"path/filepath"
	"testing"
)

func TestDiscoverModulesAndGoWork(t *testing.T) {
	repo := filepath.Clean(filepath.Join("..", "..", "testdata", "multi-module-repo"))
	discovery, err := Discover(repo)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if discovery.GoWork != "go.work" {
		t.Fatalf("go.work = %q", discovery.GoWork)
	}
	if len(discovery.Modules) != 3 {
		t.Fatalf("modules = %d, want 3: %+v", len(discovery.Modules), discovery.Modules)
	}
	for _, mod := range discovery.Modules {
		if mod.ModulePath == "" || mod.ModuleRoot == "" || mod.GoModPath == "" {
			t.Fatalf("incomplete module info: %+v", mod)
		}
		if !mod.IncludedByGoWork {
			t.Fatalf("module should be included by go.work: %+v", mod)
		}
	}
}

func TestSelectModules(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", "..", "testdata", "multi-module-repo"))
	if err != nil {
		t.Fatal(err)
	}
	discovery, err := Discover(repo)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		opts   SelectionOptions
		want   int
		absent string
	}{
		{
			name: "inside one module",
			opts: SelectionOptions{CWD: filepath.Join(repo, "service-a")},
			want: 1,
		},
		{
			name: "repo root all by default",
			opts: SelectionOptions{CWD: repo},
			want: 3,
		},
		{
			name: "explicit module",
			opts: SelectionOptions{CWD: repo, Modules: []string{"service-b"}},
			want: 1,
		},
		{
			name:   "ignore module",
			opts:   SelectionOptions{CWD: repo, IgnoreModules: []string{"shared"}},
			want:   2,
			absent: "example.com/monorepo/shared",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mods, warnings := Select(discovery, tt.opts)
			if len(warnings) != 0 {
				t.Fatalf("warnings: %+v", warnings)
			}
			got := 0
			for _, mod := range mods {
				if mod.Selected {
					got++
					if tt.absent != "" && mod.ModulePath == tt.absent {
						t.Fatalf("ignored module selected: %+v", mod)
					}
				}
			}
			if got != tt.want {
				t.Fatalf("selected = %d, want %d: %+v", got, tt.want, mods)
			}
		})
	}
}
