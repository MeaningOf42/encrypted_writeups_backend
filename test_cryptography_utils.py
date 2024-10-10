from cryptography_utils import b64encodeString, b64decodeString
import unittest
import os
import random


b64Chars = "0123456789+-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWZXYZ"


class TestB64StringUtils(unittest.TestCase):
    def test_encode_decode(self) -> None:
        """Checks that you can encode then decode bytes and end up with the same bytes"""
        testBytes: bytes = os.urandom(16)
        encodeDecode: bytes = b64decodeString(b64encodeString(testBytes))
        self.assertEqual(testBytes, encodeDecode)

    def test_decode_encode(self) -> None:
        """Checks that you can decode then encode a string and end up with the same string"""
        testString: str = "".join([random.choice(b64Chars) for i in range(16)])
        decodeEncode: str = b64encodeString(b64decodeString(testString))
        self.assertEqual(testString, decodeEncode)


class TestPasswordEncryptionDecryption(unittest.TestCase):
    pass


class TestExceptions(unittest.TestCase):
    def testB64DecodeStringThrowsTypeError(self):
        """Checks that b64decode string throws error as"""
        with self.assertRaises(RuntimeError):
            b64decodeString(os.urandom(16))


if __name__ == "__main__":
    unittest.main()
