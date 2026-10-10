#!/usr/bin/env python3
"""Seed a login item into Vaultwarden via the API, encrypting with the user
symmetric key we generated at registration (same EncString type-2 format).

Usage: seed_bw.py <server> <email> <password> <ca_cert> <name> <username> <secret>
Prints the item JSON from the server.
"""
import base64, hashlib, hmac, json, secrets, sys, urllib.request, ssl
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def b64(b): return base64.b64encode(b).decode()

def stretch(master_key, password):
    return hashlib.pbkdf2_hmac('sha256', master_key, password.encode(), 1, 32)

def stretch_enc_mac(mk):
    enc_key = hmac.new(mk, b'enc\x01', hashlib.sha256).digest()
    mac_key = hmac.new(mk, b'mac\x01', hashlib.sha256).digest()
    return enc_key, mac_key

def encrypt_cbc_hmac(plaintext, key, mac_key):
    iv = secrets.token_bytes(16)
    pad = 16 - (len(plaintext) % 16)
    pt = plaintext + bytes([pad]) * pad
    c = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = c.update(pt) + c.finalize()
    mac = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    return f"2.{b64(iv)}|{b64(ct)}|{b64(mac)}"

def api(method, path, token=None, body=None, server=None, ctx=None):
    req = urllib.request.Request(
        f"{server}{path}",
        data=json.dumps(body).encode() if body else None,
        headers={"Content-Type": "application/json",
                 **({"Authorization": f"Bearer {token}"} if token else {})},
        method=method)
    try:
        with urllib.request.urlopen(req, context=ctx) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        print("HTTP", e.code, e.read().decode()[:500])
        raise

def main():
    server, email, password, ca, name, username, secret = sys.argv[1:8]
    ctx = ssl.create_default_context(cafile=ca)

    # 1. prelogin + master key + login (same as register)
    kdf = api("POST", "/identity/accounts/prelogin", body={"email": email}, server=server, ctx=ctx)
    iters = kdf.get("kdfSettings", {}).get("iterations", 600000)
    mk = hashlib.pbkdf2_hmac('sha256', password.encode(),
                             email.strip().lower().encode(), iters, 32)
    pw_hash = stretch(mk, password)
    tokens = api("POST", "/identity/connect/token", body=None, server=server, ctx=ctx) \
        if False else None
    # token endpoint needs form encoding
    import urllib.parse
    form = urllib.parse.urlencode({
        "grant_type": "password", "username": email,
        "password": b64(pw_hash), "scope": "api offline_access",
        "client_id": "cli", "deviceType": 14, "deviceIdentifier":
        secrets.token_hex(16), "deviceName": "seed-bw"}).encode()
    req = urllib.request.Request(f"{server}/identity/connect/token", data=form,
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    with urllib.request.urlopen(req, context=ctx) as r:
        tok = json.loads(r.read())
    access = tok["access_token"]

    # 2. fetch profile -> protected symmetric key (user key), decrypt with stretched mk
    prof = api("GET", "/api/accounts/profile", token=access, server=server, ctx=ctx)
    enc_sym = prof["key"]
    typ, rest = enc_sym.split(".", 1)
    iv_s, ct_s, mac_s = rest.split("|")
    iv, ct, mac = (base64.b64decode(x) for x in (iv_s, ct_s, mac_s))
    enc_key, mac_key = stretch_enc_mac(mk)
    calc = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    assert hmac.compare_digest(calc, mac), "user key MAC failed"
    d = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
    pt = d.update(ct) + d.finalize()
    sym = pt[-64:]  # strip PKCS7
    sym_enc, sym_mac = sym[:32], sym[32:]

    # 3. encrypt item fields with user sym key
    def enc(s): return encrypt_cbc_hmac(s.encode(), sym_enc, sym_mac)
    login_obj = {
        "username": enc(username),
        "password": enc(secret),
        "totp": None,
        "uris": [{"uri": enc("https://github.com"), "match": None}],
    }
    item = {
        "type": 1,  # int (string form 422s)
        "organizationId": None,
        "folderId": None,
        "name": enc(name),
        "notes": None,
        "favorite": False,
        "login": login_obj,  # object form (verified: /api/ciphers accepts it)
    }
    created = api("POST", "/api/ciphers", token=access, body=item, server=server, ctx=ctx)
    print("SEEDED", created.get("id"), name)

if __name__ == "__main__":
    main()
