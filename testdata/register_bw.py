#!/usr/bin/env python3
"""Register a Bitwarden/Vaultwarden account via the identity API
(same crypto flow as the official client), for broker tests.

Usage: register_bw.py <server> <email> <password>
"""
import base64, hashlib, hmac, json, secrets, sys, urllib.request
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def b64(b): return base64.b64encode(b).decode()

def stretch(master_key, password):
    return hashlib.pbkdf2_hmac('sha256', master_key, password.encode(), 1, 32)

def encrypt_cbc_hmac(plaintext, key, mac_key):
    iv = secrets.token_bytes(16)
    pad = 16 - (len(plaintext) % 16)
    pt = plaintext + bytes([pad]) * pad
    c = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = c.update(pt) + c.finalize()
    mac = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()  # MAC over iv||ct (client SDK)
    # Bitwarden EncString type 2: "2.iv|ct|mac" (b64 each)
    return f"2.{b64(iv)}|{b64(ct)}|{b64(mac)}"

def register(server, email, password):
    # 1. master key from email-as-salt PBKDF2 (kdf=0, 600k iterations)
    kdf_iters = 600000
    master_key = hashlib.pbkdf2_hmac('sha256', password.encode(),
                                     email.strip().lower().encode(), kdf_iters, 32)
    pw_hash = stretch(master_key, password)

    # 2. user symmetric key (enc+mac), protected by the STRETCHED master key.
    #    Rust SDK (bw CLI 2026): Hkdf::<Sha256>::from_prk(mk).expand(b"enc"/b"mac")
    #    = HMAC-SHA256(key=mk, info||0x01) — NO extract step (mk IS the PRK).
    enc_key = hmac.new(master_key, b'enc\x01', hashlib.sha256).digest()
    mac_key_s = hmac.new(master_key, b'mac\x01', hashlib.sha256).digest()
    sym = secrets.token_bytes(64)
    protected_sym = encrypt_cbc_hmac(sym, enc_key, mac_key_s)

    # 3. RSA keypair; private key (PKCS8 DER, as the clients store it)
    #    protected by the user symmetric key
    kp = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_der = kp.private_bytes(serialization.Encoding.DER,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    pub = kp.public_key().public_bytes(serialization.Encoding.DER,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)
    protected_priv = encrypt_cbc_hmac(priv_der, sym[:32], sym[32:])

    payload = {
        "name": None, "email": email, "masterPasswordHash": b64(pw_hash),
        "key": protected_sym, "keys": {
            "publicKey": b64(pub), "encryptedPrivateKey": protected_priv},
        "token": None,
        "kdf": 0, "kdfIterations": kdf_iters,
    }
    req = urllib.request.Request(
        f"{server}/identity/accounts/register",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req) as r:
            print("REGISTER OK", r.status)
            return 0
    except urllib.error.HTTPError as e:
        print("REGISTER FAIL", e.code, e.read().decode()[:200])
        return 1

if __name__ == '__main__':
    if len(sys.argv) > 4 and sys.argv[4]:
        import ssl
        ctx = ssl.create_default_context(cafile=sys.argv[4])
        https_handler = urllib.request.HTTPSHandler(context=ctx)
        opener = urllib.request.build_opener(https_handler)
        urllib.request.urlopen = opener.open
    sys.exit(register(sys.argv[1], sys.argv[2], sys.argv[3]))
