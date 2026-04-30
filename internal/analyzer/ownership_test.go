package analyzer

import (
	"testing"

	"github.com/faultline-go/faultline/internal/ownership"
	"github.com/faultline-go/faultline/internal/report"
)

func TestOwnershipFindings(t *testing.T) {
	tests := []struct {
		name       string
		pkg        report.PackageRisk
		resolution ownership.Resolution
		wantIDs    []string
	}{
		{
			name: "ownership mismatch",
			resolution: ownership.Resolution{
				CodeownersOwners:  []string{"@api-team"},
				DominantGitAuthor: "alice@example.com",
				DominantGitOwner:  "@payments-platform",
				DominantGitShare:  0.75,
			},
			wantIDs: []string{"FL-OWN-003"},
		},
		{
			name: "missing module owner",
			pkg: report.PackageRisk{
				ModulePath: "example.com/monorepo/service-a",
				ModuleRoot: "service-a",
			},
			resolution: ownership.Resolution{
				ModuleOwnerMissing: true,
			},
			wantIDs: []string{"FL-OWN-004"},
		},
		{
			name: "matching owners",
			resolution: ownership.Resolution{
				CodeownersOwners:  []string{"@payments-platform"},
				DominantGitAuthor: "alice@example.com",
				DominantGitOwner:  "@payments-platform",
				DominantGitShare:  0.75,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ownershipFindings(tt.pkg, tt.resolution)
			if len(got) != len(tt.wantIDs) {
				t.Fatalf("findings = %+v, want ids %v", got, tt.wantIDs)
			}
			for i, id := range tt.wantIDs {
				if got[i].ID != id {
					t.Fatalf("finding[%d].ID = %q, want %q", i, got[i].ID, id)
				}
				if len(got[i].Evidence) == 0 {
					t.Fatalf("finding %s missing evidence", id)
				}
			}
		})
	}
}
