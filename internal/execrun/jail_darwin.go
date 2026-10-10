//go:build darwin

package execrun

import "os/exec"

// sandboxProfile denies every network operation while leaving the filesystem
// alone. `deny network*` covers inet, inet6 and unix sockets, and the sandbox
// is inherited by descendants, so a shell cannot fork its way out.
const sandboxProfile = `(version 1)(allow default)(deny network*)`

// jailNoNetworkPlatform confines cmd with sandbox-exec. It is marked
// deprecated in the man page but is the mechanism Apple still ships and uses;
// it preserves exit codes, writes nothing to stderr, and confines descendants.
func jailNoNetworkPlatform(cmd *exec.Cmd) error {
	sandboxExec, err := exec.LookPath("sandbox-exec")
	if err != nil {
		return errNoJail("sandbox-exec not found on this system")
	}
	// argv[0] stays the real executable path: destination binding has already
	// validated it, and sandbox-exec execs it directly.
	cmd.Args = append([]string{sandboxExec, "-p", sandboxProfile, cmd.Path}, cmd.Args[1:]...)
	cmd.Path = sandboxExec
	return nil
}

// jailUnavailableHint is unused on darwin: sandbox-exec either resolves at
// wrap time or the wrap already failed with a clear reason.
const jailUnavailableHint = "sandbox-exec could not confine the process"
