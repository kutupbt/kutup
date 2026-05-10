package main

import "github.com/kutupbulut/kutup/cmd/kutup/cmd"

// version is set via -ldflags="-X main.version=..." at goreleaser build
// time. For `go install`-built binaries we leave it empty and let the
// version subcommand fall back to runtime/debug.ReadBuildInfo, which
// surfaces the module pseudo-version (e.g. v0.0.0-20260510-abc123def).
var version string

func main() {
	cmd.SetVersion(version)
	cmd.Execute()
}
