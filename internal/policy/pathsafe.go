package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// PathSafe reports whether an executable is out of reach of a non-root
// attacker: owned by root, not group/world-writable, and sitting in a
// directory with the same properties (a writable directory means the binary
// can simply be replaced).
//
// This is what makes an exec allow-list mean anything. /opt/homebrew/bin is
// group-admin writable on macOS, so allow-listing a Homebrew binary lets any
// process running as the user swap it for one that prints its environment.
func PathSafe(path string) (bool, string) {
	for _, p := range []string{path, filepath.Dir(path)} {
		fi, err := os.Stat(p)
		if err != nil {
			return false, fmt.Sprintf("%s: %v", p, err)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return false, "cannot read ownership of " + p
		}
		if st.Uid != 0 {
			return false, fmt.Sprintf("%s is owned by uid %d, not root — the agent's user can replace it", p, st.Uid)
		}
		if fi.Mode().Perm()&0022 != 0 {
			return false, fmt.Sprintf("%s is group/world-writable (%04o)", p, fi.Mode().Perm())
		}
	}
	return true, ""
}

// interpreters are binaries that run arbitrary code supplied as arguments or
// stdin. Allow-listing one is equivalent to allow-listing everything: the
// agent writes `printf %s "$PW" | base64` and output masking never sees the
// value it is meant to conceal.
var interpreters = []string{
	"sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish",
	"python", "python2", "python3", "perl", "ruby", "node", "deno", "bun",
	"php", "lua", "tclsh", "osascript", "awk", "gawk",
	"env", "xargs", "nohup", "timeout", "script", "expect",
	"sudo", "doas", "ssh", "scp", "docker", "podman", "kubectl",
	"curl", "wget", "nc", "ncat", "socat", "telnet",
}

// IsInterpreter reports whether the path looks like a shell, interpreter, or
// generic network client. Version suffixes are trimmed (python3.11 -> python3).
func IsInterpreter(path string) bool {
	base := filepath.Base(path)
	for _, name := range interpreters {
		if base == name || strings.HasPrefix(base, name+".") {
			return true
		}
	}
	return false
}
