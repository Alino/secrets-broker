package execrun

import (
	"os/exec"
)

// Network jailing for a child that receives a secret.
//
// Threat: destination binding decides WHICH executable may receive a
// credential, but nothing stops that executable from sending it somewhere
// else. `network: "none"` closes that gap for the local-tool case (jq, git
// on a local repo, a formatter, a build) where the tool has no business
// talking to the network at all.
//
// Two rules govern this file:
//
//  1. It must FAIL CLOSED. If the platform cannot enforce the jail, the exec
//     is refused. A security control that silently degrades into a no-op is
//     worse than an absent one, because the policy file still claims it.
//     Note that on Linux the failure can only surface when the child is
//     STARTED, so run.go treats a start error under a jail as a denial.
//  2. Per-HOST egress binding is deliberately NOT offered: enforcing it would
//     require terminating the child's TLS, and a hostname allow-list that can
//     be defeated by an IP literal or a redirect would be worse than none.
//     "none" is the honest, enforceable unit.
//
// Mechanisms, both of which also confine descendants:
//
//	darwin: sandbox-exec with (deny network*)
//	linux:  CLONE_NEWUSER|CLONE_NEWNET (empty network namespace)
//
// Anything else refuses.

// jailNoNetwork rewraps cmd so it (and every process it spawns) has no network
// access. A non-nil error means this platform has no mechanism the broker
// trusts, and the caller MUST refuse the exec.
func jailNoNetwork(cmd *exec.Cmd) error {
	return jailNoNetworkPlatform(cmd)
}

func errNoJail(why string) error {
	return simpleErr("DENIED: policy requires network:none but it cannot be enforced here (" + why +
		"); refusing rather than running the child unconfined")
}
