package version

import (
	"fmt"
	"runtime"
	"strings"
)

// These are set via -ldflags at build time.
var (
	Version   = "0.1.0"
	Commit    = "unknown"
	BuildDate = "unknown"
)

type Info struct {
	Version   string
	Commit    string
	Date      string
	GoVersion string
	OS        string
	Arch      string
}

func Get() Info {
	return Info{
		Version:   sane(Version, "0.1.0"),
		Commit:    sane(Commit, "unknown"),
		Date:      sane(BuildDate, "unknown"),
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
}

func String() string {
	info := Get()
	if info.Commit == "unknown" {
		return info.Version
	}
	return info.Version + " (" + info.Commit + ")"
}

func FullString() string {
	info := Get()
	return fmt.Sprintf("version: %s\ncommit: %s\ndate: %s\ngo: %s\nos/arch: %s/%s",
		info.Version, info.Commit, info.Date, info.GoVersion, info.OS, info.Arch)
}

func sane(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
