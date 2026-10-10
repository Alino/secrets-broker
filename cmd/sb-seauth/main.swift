// sb-seauth — the Secure Enclave side of human approval. Runs as the console
// user (biometric enrollment is per-user); needs no root.
//
//   sb-seauth keygen [--force]     create the approval key, print its public
//                                  half (base64 X9.63). Idempotent unless --force.
//   sb-seauth sign <nonce> <reason>
//                                  sign the nonce, forcing a fresh Touch ID
//                                  that shows <reason>; print signature base64.
//
// The private key lives in the Secure Enclave, cannot be exported, and requires
// a biometric on every use. A signature therefore proves a fresh human touch
// bound to exactly the nonce signed — it cannot be replayed onto another
// request, which is what Authorization Services could not guarantee.
import Foundation
import Security
import LocalAuthentication

let tag = "dev.secretsbroker.approval".data(using: .utf8)!
let accessGroup = "dev.secretsbroker"

func die(_ msg: String, _ code: Int32 = 2) -> Never {
    FileHandle.standardError.write("sb-seauth: \(msg)\n".data(using: .utf8)!)
    exit(code)
}

func loadKey() -> SecKey? {
    let q: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tag,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrAccessGroup as String: accessGroup,
        kSecUseDataProtectionKeychain as String: true,
        kSecReturnRef as String: true,
    ]
    var item: CFTypeRef?
    return SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess ? (item as! SecKey) : nil
}

func publicB64(_ priv: SecKey) -> String {
    guard let pub = SecKeyCopyPublicKey(priv),
          let data = SecKeyCopyExternalRepresentation(pub, nil) as Data? else {
        die("cannot export public key")
    }
    return data.base64EncodedString() // 04||X||Y for P-256
}

func createKey() -> SecKey {
    var err: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .biometryCurrentSet], &err) else {
        die("access control: \(err!.takeRetainedValue())")
    }
    let attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag,
            kSecAttrAccessControl as String: access,
            kSecAttrAccessGroup as String: accessGroup,
        ],
        kSecUseDataProtectionKeychain as String: true,
    ]
    guard let priv = SecKeyCreateRandomKey(attrs as CFDictionary, &err) else {
        die("cannot create Secure Enclave key: \(err!.takeRetainedValue())")
    }
    return priv
}

func deleteKey() {
    SecItemDelete([
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tag,
        kSecAttrAccessGroup as String: accessGroup,
        kSecUseDataProtectionKeychain as String: true,
    ] as CFDictionary)
}

let args = CommandLine.arguments
guard args.count >= 2 else { die("usage: sb-seauth keygen [--force] | sign <nonce> <reason>") }

switch args[1] {
case "keygen":
    if args.contains("--force") { deleteKey() }
    if let existing = loadKey() {
        print(publicB64(existing)) // idempotent: report the key already present
    } else {
        print(publicB64(createKey()))
    }

case "sign":
    guard args.count >= 3 else { die("usage: sb-seauth sign <nonce> <describe>") }
    let nonce = args[2]
    // The description is signed alongside the nonce, so the daemon can confirm
    // the human saw exactly this command. The shown reason wraps it for
    // legibility but the signed bytes are precisely nonce + "\n" + describe.
    let describe = args.count >= 4 ? args[3] : ""
    let message = Data((nonce + "\n" + describe).utf8)
    let reason = "secrets-broker — approve:\n\n" + describe
    guard nonce.count == 16, nonce.allSatisfy({ "0123456789abcdef".contains($0) }) else {
        die("invalid nonce")
    }
    guard loadKey() != nil else { die("no approval key — run: sudo sb install") }

    // The reason shown on the biometric prompt comes from the caller (the
    // broker's own description of the request, relayed by `sb approve`), never
    // chosen by the agent.
    let ctx = LAContext()
    ctx.localizedReason = reason
    // Attaching the context makes SecKeyCreateSignature present the prompt with
    // this reason; biometryCurrentSet on the key forces a fresh touch.
    let signer: SecKey = {
        let q: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrAccessGroup as String: accessGroup,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: ctx,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess else {
            die("cannot load approval key for signing")
        }
        return item as! SecKey
    }()

    var err: Unmanaged<CFError>?
    guard let sig = SecKeyCreateSignature(
        signer, .ecdsaSignatureMessageX962SHA256,
        message as CFData, &err) as Data? else {
        die("signing failed (declined?): \(err!.takeRetainedValue())", 1)
    }
    print(sig.base64EncodedString())

default:
    die("unknown command \(args[1])")
}
