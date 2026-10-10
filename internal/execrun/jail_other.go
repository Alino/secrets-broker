//go:build !darwin && !linux

package execrun

import (
	"os/exec"
	"runtime"
)

// jailNoNetworkPlatform refuses on platforms with no mechanism the broker has
// verified. Failing closed is the contract: a policy that asks for
// network:none must never silently run unconfined.
func jailNoNetworkPlatform(cmd *exec.Cmd) error {
	return errNoJail("no verified network jail on " + runtime.GOOS)
}

const jailUnavailableHint = "no verified network jail on this platform"
