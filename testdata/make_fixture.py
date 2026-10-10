#!/usr/bin/env python3
"""Generate a synthetic 1Password 7 .opvault fixture for tests.

Implements the opdata01 format exactly as the vendored reader expects:
  profile.js: "var profile=" + JSON with salt, iterations, masterKey (opdata01
  of 64-byte master key), overviewKey (opdata01 of 64-byte overview key)
  band_X.js: "ld(" + JSON {uuid: item} where item has 'o' (opdata01 overview
  JSON w/ title), 'k' (raw AES-CBC of 64-byte item keys + HMAC), 'd' (opdata01
  detail JSON w/ fields), 'trashed': false, 'category', 'created', 'updated',
  'f' (folder UUID or null), 'h' (hmac hex)
Usage: make_fixture.py <outdir> [password]
"""
import base64, hashlib, hmac, json, os, secrets, struct, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def pad(b):
    # opdata01 pads at the FRONT: plaintext must sit at the END of the block
    n = 16 - (len(b) % 16)
    if n == 0:
        n = 16
    return secrets.token_bytes(n) + b

def opdata01_encrypt(plaintext, enc_key, mac_key):
    iv = secrets.token_bytes(16)
    e = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ciphertext = e.update(pad(plaintext)) + e.finalize()
    body = b'opdata01' + struct.pack('<Q', len(plaintext)) + iv + ciphertext
    mac = hmac.new(mac_key, body, hashlib.sha256).digest()
    return body + mac

def aes_cbc_encrypt(plaintext, key):
    iv = secrets.token_bytes(16)
    c = Cipher(algorithms.AES(key), modes.CBC(iv))
    e = c.encryptor()
    return iv + e.update(pad(plaintext)) + e.finalize()

def main():
    outdir = sys.argv[1]
    password = sys.argv[2] if len(sys.argv) > 2 else 'correct horse battery staple'
    profile_dir = os.path.join(outdir, 'default')
    os.makedirs(profile_dir, exist_ok=True)

    salt = secrets.token_bytes(16)
    iterations = 10000  # low for test speed

    # derive master password keys (64 bytes -> 32 enc + 32 mac)
    derived = hashlib.pbkdf2_hmac('sha512', password.encode(), salt, iterations, 64)
    d_enc, d_mac = derived[:32], derived[32:]

    master_key = secrets.token_bytes(64)
    overview_key = secrets.token_bytes(64)

    profile = {
        'lastUpdatedBy': 'pytest',
        'updatedAt': 1,
        'profileName': 'default',
        'profileUuid': secrets.token_hex(16),
        'salt': base64.b64encode(salt).decode(),
        'iterations': iterations,
        'masterKey': base64.b64encode(opdata01_encrypt(master_key, d_enc, d_mac)).decode(),
        'overviewKey': base64.b64encode(opdata01_encrypt(overview_key, d_enc, d_mac)).decode(),
        'uuid': int(1).to_bytes(8, 'little').hex(),
    }
    with open(os.path.join(profile_dir, 'profile.js'), 'w') as f:
        f.write('var profile=' + json.dumps(profile))

    # sha512 of decrypted master/overview key -> item enc/mac keys
    mk = hashlib.sha512(master_key).digest()
    m_enc, m_mac = mk[:32], mk[32:]
    ok = hashlib.sha512(overview_key).digest()
    o_enc, o_mac = ok[:32], ok[32:]

    # one item: GitHub login
    item_keys = secrets.token_bytes(64)
    overview = {'title': 'GitHub', 'ainfo': 'alex@example.com', 'url': 'https://github.com'}
    detail = {'fields': [
        {'name': 'username', 'value': 'alex@example.com', 'type': 'T', 'designation': 'username'},
        {'name': 'password', 'value': 'ghp_SuperSecretFixtureToken123', 'type': 'P', 'designation': 'password'},
    ], 'notesPlain': ''}
    uuid = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    k_blob = aes_cbc_encrypt(item_keys, m_enc)
    k_mac = hmac.new(m_mac, k_blob, hashlib.sha256).digest()

    item = {
        'uuid': uuid,
        'category': '001',  # login
        'created': int(1).to_bytes(8, 'little').hex(),
        'updated': int(1).to_bytes(8, 'little').hex(),
        'f': None,
        'h': hmac.new(m_mac, uuid.encode(), hashlib.sha256).hexdigest(),
        'trashed': False,
        'o': base64.b64encode(opdata01_encrypt(json.dumps(overview).encode(), o_enc, o_mac)).decode(),
        'k': base64.b64encode(k_blob + k_mac).decode(),
    }
    # 'd' is encrypted lazily with the ITEM keys (decrypted on Detail())
    ik_enc, ik_mac = item_keys[:32], item_keys[32:]
    item['d'] = base64.b64encode(opdata01_encrypt(json.dumps(detail).encode(), ik_enc, ik_mac)).decode()

    with open(os.path.join(profile_dir, 'band_0.js'), 'w') as f:
        f.write('ld(' + json.dumps({uuid: item}))

    print('fixture written to', outdir)

if __name__ == '__main__':
    main()
