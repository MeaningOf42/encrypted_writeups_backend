"""
Cryptography utility used to generate
"""

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode as b64e
from base64 import urlsafe_b64decode as b64d


KEY_DERIVE_ITERATIONS = 480_000


def b64encodeString(toEncode: bytes) -> str:
    return b64e(toEncode).decode("utf-8")


def b64decodeString(toDecode: str) -> bytes:
    return b64d(toDecode.encode("utf-8"))


SALT_STR_LEN = len(os.urandom(16))


def genKeyFromPasswordAndSalt(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KEY_DERIVE_ITERATIONS,
    )
    return kdf.derive(b64decodeString(password))


def encryptStringFromPassword(stringToEncrypt: str, password: str) -> str:
    salt: bytes = os.urandom(16)
    saltString = b64encodeString(salt)
    key: bytes = genKeyFromPasswordAndSalt(password, salt)
    bytesToEncrypt: bytes = b64decodeString(stringToEncrypt)
    encryptedMessageString: str = b64encodeString(Fernet(key).encrypt(bytesToEncrypt))
    return saltString + encryptedMessageString


def decryptStringFromPassword(encryptedString: str, password: str) -> str:
    encryptedMessage: bytes = b64decodeString(encryptedString[SALT_STR_LEN:])
    salt: bytes = b64decodeString(encryptedString[:SALT_STR_LEN])
    key: bytes = genKeyFromPasswordAndSalt(password, salt)

    return b64encodeString(Fernet(key).decrypt(encryptedMessage))
