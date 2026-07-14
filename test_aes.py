"""
test_aes.py - Validation script for FIPS-197 AES test vectors
"""

import unittest
from aes import AES


class TestAESComplianceVectors(unittest.TestCase):
    def test_official_fips_197_test_matrices(self) -> None:
        # FIPS-197 AES-128 test vectors
        shared_plaintext = bytes.fromhex("00112233445566778899AABBCCDDEEFF")

        # Configuration 1: AES-128 Bit Evaluation
        key_128_bit = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
        cipher_128_bit = bytes.fromhex("69C4E0D86A7B0430D8CDB78070B4C55A")
        
        engine_aes_128 = AES(key_128_bit)
        self.assertEqual(engine_aes_128.encrypt_block(shared_plaintext), cipher_128_bit)
        self.assertEqual(engine_aes_128.decrypt_block(cipher_128_bit), shared_plaintext)

        # Configuration 2: AES-192 Bit Evaluation
        key_192_bit = bytes.fromhex("000102030405060708090A0B0C0D0E0F1011121314151617")
        cipher_192_bit = bytes.fromhex("DDA97CA4864CDFE06EAF70A0EC0D7191")
        
        engine_aes_192 = AES(key_192_bit)
        self.assertEqual(engine_aes_192.encrypt_block(shared_plaintext), cipher_192_bit)
        self.assertEqual(engine_aes_192.decrypt_block(cipher_192_bit), shared_plaintext)

        # Configuration 3: AES-256 Bit Evaluation
        key_256_bit = bytes.fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
        cipher_256_bit = bytes.fromhex("8EA2B7CA516745BFEAFE77B19F7E1582")
        
        engine_aes_256 = AES(key_256_bit)
        self.assertEqual(engine_aes_256.encrypt_block(shared_plaintext), cipher_256_bit)
        self.assertEqual(engine_aes_256.decrypt_block(cipher_256_bit), shared_plaintext)


if __name__ == "__main__":
    unittest.main()
