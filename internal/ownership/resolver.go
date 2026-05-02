package ownership

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/faultline-go/faultline/internal/policy"
	"github.com/faultline-go/faultline/internal/report"
)

const (
	SourceModuleOwner = "module"
	SourceCodeowners  = "CODEOWNERS"
	SourceGitAlias    = "git_alias"
	SourceGitAuthor   = "git_author"
	SourceUnknown     = "unknown"
)

// ResolveInput contains the ownership signals available for one package.
type ResolveInput struct {
	Config         policy.OwnersConfig
	ModulePath     string
	ModuleRoot     string
	RepoRoot       string
	CodeownersRoot string
	PackageDir     string
	Codeowners     *Codeowners
	AuthorCounts   map[string]int
	MultiModule    bool
}

// Resolution is the selected package owner plus the candidates and diagnostics
// that explain how the selection was made.
type Resolution struct {
	Owner              string
	Source             string
	Confidence         float64
	Candidates         []report.OwnerCandidate
	Evidence           []report.Evidence
	CodeownersOwners   []string
	CodeownersFile     string
	CodeownersLine     int
	CodeownersPattern  string
	DominantGitAuthor  string
	DominantGitOwner   string
	DominantGitShare   float64
	ModuleOwnerMissing bool
}

// Resolve combines explicit module owners, CODEOWNERS, and git authorship using
// Faultline's documented precedence. It does not turn git authorship into a hard
// authority; author-derived owners intentionally receive lower confidence.
func Resolve(in ResolveInput) Resolution {
	var out Resolution
	moduleOwner := moduleOwnerFor(in.Config, in.ModulePath, in.ModuleRoot)
	if in.MultiModule && strings.TrimSpace(in.ModulePath) != "" && moduleOwner == "" {
		out.ModuleOwnerMissing = true
	}
	if moduleOwner != "" {
		out.Candidates = append(out.Candidates, report.OwnerCandidate{
			Owner:      moduleOwner,
			Source:     SourceModuleOwner,
			Confidence: 1.0,
			Detail:     in.ModulePath,
		})
		out.Evidence = append(out.Evidence, report.Evidence{Key: "module_owner", Value: moduleOwner, Source: SourceModuleOwner})
	}

	if in.Codeowners != nil {
		match := in.Codeowners.MatchForPackage(in.CodeownersRoot, in.PackageDir)
		owners := match.Owners
		out.CodeownersOwners = append([]string{}, owners...)
		out.CodeownersFile = safeRel(in.CodeownersRoot, match.File)
		out.CodeownersLine = match.Line
		out.CodeownersPattern = match.Pattern
		for _, owner := range owners {
			out.Candidates = append(out.Candidates, report.OwnerCandidate{
				Owner:      owner,
				Source:     SourceCodeowners,
				Confidence: 0.9,
				Detail:     fmt.Sprintf("%s:%d %s", out.CodeownersFile, match.Line, match.Pattern),
			})
			out.Evidence = append(out.Evidence, report.Evidence{Key: "codeowners_owner", Value: owner, Source: SourceCodeowners})
		}
		if len(owners) > 0 {
			out.Evidence = append(out.Evidence,
				report.Evidence{Key: "codeowners_matched_file", Value: out.CodeownersFile, Source: SourceCodeowners},
				report.Evidence{Key: "codeowners_matched_line", Value: fmt.Sprintf("%d", match.Line), Source: SourceCodeowners},
				report.Evidence{Key: "codeowners_matched_pattern", Value: match.Pattern, Source: SourceCodeowners},
				report.Evidence{Key: "codeowners_matched_owners", Value: strings.Join(owners, ","), Source: SourceCodeowners},
			)
		}
	}

	if author, share := DominantOwner(in.AuthorCounts); author != "" {
		out.DominantGitAuthor = author
		out.DominantGitShare = share
		owner, aliased := ResolveAlias(in.Config.Aliases, author)
		out.DominantGitOwner = owner
		source := SourceGitAuthor
		confidence := 0.45
		detail := author
		if aliased {
			source = SourceGitAlias
			confidence = 0.65
			detail = fmt.Sprintf("%s via %s", author, owner)
			out.Evidence = append(out.Evidence, report.Evidence{Key: "ownership_alias", Value: owner + "=" + author, Source: "config"})
		}
		out.Candidates = append(out.Candidates, report.OwnerCandidate{
			Owner:      owner,
			Source:     source,
			Confidence: confidence,
			Detail:     detail,
		})
		out.Evidence = append(out.Evidence,
			report.Evidence{Key: "dominant_git_author", Value: author, Source: "git"},
			report.Evidence{Key: "dominant_git_owner", Value: owner, Source: source},
			report.Evidence{Key: "dominant_git_share", Value: fmt.Sprintf("%.2f", share), Source: "git"},
		)
	}

	out.Owner, out.Source, out.Confidence = selectOwner(out.Candidates)
	if out.Owner == "" {
		out.Source = SourceUnknown
	}
	out.Evidence = append(out.Evidence,
		report.Evidence{Key: "selected_owner", Value: valueOrUnknown(out.Owner), Source: "ownership"},
		report.Evidence{Key: "owner_source", Value: out.Source, Source: "ownership"},
		report.Evidence{Key: "ownership_confidence", Value: fmt.Sprintf("%.2f", out.Confidence), Source: "ownership"},
	)
	for _, candidate := range out.Candidates {
		out.Evidence = append(out.Evidence, report.Evidence{
			Key:    "owner_candidate",
			Value:  candidate.Owner + " (" + candidate.Source + ")",
			Source: "ownership",
		})
	}
	return out
}

// ResolveAlias maps an authorship identity to the configured enterprise owner,
// if an alias contains the identity. The returned owner is the alias key.
func ResolveAlias(aliases map[string][]string, identity string) (string, bool) {
	identity = strings.TrimSpace(identity)
	if identity == "" {
		return "", false
	}
	keys := make([]string, 0, len(aliases))
	for key := range aliases {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, owner := range keys {
		if sameIdentity(owner, identity) {
			return owner, true
		}
		members := append([]string{}, aliases[owner]...)
		sort.Strings(members)
		for _, member := range members {
			if sameIdentity(member, identity) {
				return owner, true
			}
		}
	}
	return identity, false
}

func moduleOwnerFor(cfg policy.OwnersConfig, modulePath, moduleRoot string) string {
	keys := make([]string, 0, len(cfg.Modules))
	for key := range cfg.Modules {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if key != modulePath && key != moduleRoot {
			continue
		}
		if owner := strings.TrimSpace(cfg.Modules[key].Owner); owner != "" {
			return owner
		}
	}
	return ""
}

func selectOwner(candidates []report.OwnerCandidate) (string, string, float64) {
	precedence := map[string]int{
		SourceModuleOwner: 0,
		SourceCodeowners:  1,
		SourceGitAlias:    2,
		SourceGitAuthor:   2,
	}
	var best report.OwnerCandidate
	found := false
	bestRank := len(precedence) + 1
	for _, candidate := range candidates {
		rank, ok := precedence[candidate.Source]
		if !ok {
			continue
		}
		if !found || rank < bestRank || (rank == bestRank && candidate.Owner < best.Owner) {
			best = candidate
			bestRank = rank
			found = true
		}
	}
	if !found {
		return "", "", 0
	}
	return best.Owner, best.Source, best.Confidence
}

func sameIdentity(left, right string) bool {
	left = strings.TrimSpace(left)
	right = strings.TrimSpace(right)
	if strings.Contains(left, "@") && strings.Contains(right, "@") && !strings.HasPrefix(left, "@") && !strings.HasPrefix(right, "@") {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func valueOrUnknown(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}

func safeRel(root, p string) string {
	if root == "" || p == "" {
		return filepath.ToSlash(p)
	}
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return filepath.ToSlash(p)
	}
	return filepath.ToSlash(rel)
}
