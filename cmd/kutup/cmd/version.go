package cmd

import (
	"encoding/json"
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// ldflagsVersion is set by main.SetVersion at startup. Goreleaser
// injects it via `-X main.version=v0.1.0` on tagged builds; `go install`
// builds leave it empty.
var ldflagsVersion string

// SetVersion is called from main.main with the value injected at build
// time (or empty for `go install`). Stored package-private so the
// version command can render it.
func SetVersion(v string) { ldflagsVersion = v }

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the kutup CLI version + build info",
	Args:  cobra.NoArgs,
	Run:   runVersion,
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

// resolveVersion returns the most informative version string available:
//   - The ldflags-injected value (preferred; set by goreleaser).
//   - debug.ReadBuildInfo's main.Version, which is the module pseudo-
//     version for `go install` users (e.g. v0.0.0-20260510-abc123def).
//   - "(devel)" as a last resort — Go's own fallback for in-tree builds.
func resolveVersion() (string, *debug.BuildInfo) {
	bi, _ := debug.ReadBuildInfo()
	if ldflagsVersion != "" {
		return ldflagsVersion, bi
	}
	if bi != nil && bi.Main.Version != "" {
		return bi.Main.Version, bi
	}
	return "(devel)", bi
}

// vcsRevision pulls the embedded git revision (and dirty flag) out of
// build info. Available on Go ≥ 1.18 with -buildvcs=true (default).
func vcsRevision(bi *debug.BuildInfo) (rev string, dirty bool) {
	if bi == nil {
		return "", false
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	return
}

func runVersion(_ *cobra.Command, _ []string) {
	v, bi := resolveVersion()
	rev, dirty := vcsRevision(bi)

	if jsonOut {
		out := map[string]any{
			"version":  v,
			"goVersion": runtime.Version(),
			"os":       runtime.GOOS,
			"arch":     runtime.GOARCH,
		}
		if rev != "" {
			out["commit"] = rev
			out["dirty"] = dirty
		}
		b, _ := json.Marshal(out)
		fmt.Println(string(b))
		return
	}

	fmt.Printf("kutup %s\n", v)
	if rev != "" {
		dstr := ""
		if dirty {
			dstr = " (dirty)"
		}
		fmt.Printf("commit %s%s\n", short(rev), dstr)
	}
	fmt.Printf("%s/%s, %s\n", runtime.GOOS, runtime.GOARCH, runtime.Version())
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
