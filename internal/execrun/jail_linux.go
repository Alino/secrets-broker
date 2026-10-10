//go:build linux

package execrun

import (
	"os"
	"os/exec"
	"syscall"
)

// jailNoNetworkPlatform confines cmd to an empty network namespace on Linux.
//
// It uses CLONE_NEWUSER|CLONE_NEWNET directly rather than shelling out to
// `unshare`: no dependency on util-linux being installed, no argv rewriting,
// and the child is still exec'd by us so exit codes and pipes are unchanged.
// A new user namespace is what makes CLONE_NEWNET available to an
// unprivileged process; the uid/gid maps keep the child's identity stable
// inside it, so file access is unaffected.
//
// A fresh network namespace contains only a down loopback interface, so the
// child and every process it spawns have no route to anywhere — the same
// guarantee as sandbox-exec's `(deny network*)` on macOS.
//
// This can still fail at spawn time where unprivileged user namespaces are
// disabled: the Docker/Podman default seccomp profile blocks the unshare
// syscall, `kernel.unprivileged_userns_clone=0` on older Debian/Ubuntu, and
// some hardened kernels (Grsecurity) remove it entirely. That failure surfaces
// as an EPERM from Start(), which Run turns into a refusal — never a silent
// unconfined exec.
func jailNoNetworkPlatform(cmd *exec.Cmd) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET
	cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{
		{ContainerID: 0, HostID: os.Getuid(), Size: 1},
	}
	cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{
		{ContainerID: 0, HostID: os.Getgid(), Size: 1},
	}
	return nil
}

// jailUnavailableHint explains an EPERM at spawn time, so the user is told how
// to fix it rather than just that it failed.
const jailUnavailableHint = "unprivileged user namespaces are unavailable " +
	"(blocked by the container seccomp profile, or kernel.unprivileged_userns_clone=0)"
