package geogrep

import "fmt"

var (
	// Version is the application version. It can be overridden via -ldflags.
	Version = "0.2.1"
	// Commit is the source revision. It can be overridden via -ldflags.
	Commit = "unknown"
	// BuildDate is the UTC build timestamp. It can be overridden via -ldflags.
	BuildDate = "unknown"
)

func printVersion() {
	fmt.Printf("geogrep version %s\n", Version)
	fmt.Printf("commit %s\n", Commit)
	fmt.Printf("built %s\n", BuildDate)
}
