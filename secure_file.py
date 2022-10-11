import secrets
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import sys

backend = default_backend()
iterations = 1_000_000

def _derive_key(password: bytes, salt: bytes, iterations: int = iterations) -> bytes:
    """Derive a secret key from a given password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=iterations, backend=backend)
    return b64e(kdf.derive(password))

def password_encrypt(message: bytes, password: str, iterations: int = iterations) -> bytes:
    salt = secrets.token_bytes(16)
    key = _derive_key(password.encode(), salt, iterations)
    return b64e(
        b'%b%b%b' % (
            salt,
            iterations.to_bytes(4, 'big'),
            b64d(Fernet(key).encrypt(message)),
        )
    )

def password_decrypt(token: bytes, password: str) -> bytes:
    decoded = b64d(token)
    salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
    iterations = int.from_bytes(iter, 'big')
    key = _derive_key(password.encode(), salt, iterations)
    return Fernet(key).decrypt(token)


def usage_error():
    print("Usage: 'python3 secure_file.py <mode>[encrypt: '-e', decrypt: '-d'] '<password>' <target_filename>'")
    sys.exit(1) 

if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage_error()
    mode = sys.argv[1]
    if mode != "-e" and mode != "-d" or len(sys.argv) < 4:
        usage_error()
    password = sys.argv[2]
    target_encrypt_file = sys.argv[3]
    if mode == "-e":
        print("Mode: encrypt")
        try:
            out_encrypted_file = target_encrypt_file.split(".")
            if len(out_encrypted_file) > 1:
                out_encrypted_file = out_encrypted_file[0] + "_encrypted." + out_encrypted_file[1]
            else:
                out_encrypted_file = out_encrypted_file[0] + "_encrypted"
            with open(target_encrypt_file, "rb") as in_file, open(out_encrypted_file, "wb") as out_file:
                encrypt_bytes = password_encrypt(in_file.read(), password)
                out_file.write(encrypt_bytes)
            print("Encrypted version of '" + target_encrypt_file + "' created with name '" + out_encrypted_file + "'")
        except IOError:
            print("error: IO error, make sure file to encrypt '" + target_encrypt_file + "' exists in this directory")
            sys.exit(1)
        print("ENCRYPT SUCCESS")
    else:
        print("Mode: decrypt")
        try:
            out_decrypted_file = target_encrypt_file.split(".")
            out_decrypted_file[0] = out_decrypted_file[0].split("_encrypted")[0]
            if len(out_decrypted_file) > 1:
                out_decrypted_file = out_decrypted_file[0] + "_decrypted." + out_decrypted_file[1]
            else:
                out_decrypted_file = out_decrypted_file[0] + "_decrypted"
            with open(target_encrypt_file, "rb") as in_file, open(out_decrypted_file, "wb") as out_file:
                encrypt_bytes = in_file.read()
                try:
                    decrypted = password_decrypt(encrypt_bytes, password)
                except:
                    print("error: incorrect password")
                    sys.exit(1)
                out_file.write(decrypted)
            print("Decrypted version of '" + target_encrypt_file + "' created with name '" + out_decrypted_file + "'")
        except IOError:
            print("error: IO error, make sure encrypted file '" + target_encrypt_file + "' is spelled correctly")
            sys.exit(1)
        print("DECRYPT SUCCESS")
