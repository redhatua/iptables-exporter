// Package buildinfo carries version metadata injected at link time.
package buildinfo

import (
	"fmt"
	"runtime"
)

// Version and Revision are overridden with -ldflags "-X ...".
var (
	Version  = "dev"
	Revision = "unknown"
)

// String returns a one-line human readable version.
func String() string {
	return fmt.Sprintf("iptables-exporter %s (revision %s, %s)", Version, Revision, runtime.Version())
}
