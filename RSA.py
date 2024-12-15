"""
RSA Encryption Module

This module provides RSA-based asymmetric encryption for key generation, encryption,
and decryption. It uses cryptographically secure prime generation and modular arithmetic.

Classes:
    RSA: Implements RSA public-key cryptosystem functionalities.

Example Usage:
    rsa = RSA(bit_length=2048)
    plaintext = 12345
    encrypted = rsa.encrypt_int(plaintext)
    decrypted = rsa.decrypt_int(encrypted)
    print(decrypted)  # Output: 12345
"""

import secrets
import os
import pickle

class RSA:
    """
    RSA Asymmetric Encryption Implementation.

    Attributes:
        bit_length (int): The length of the RSA key in bits.
        public_key (tuple): The public key as a tuple (n, e).
        private_key (tuple): The private key as a tuple (n, d).
        key_path (str): File path for saving or loading RSA keys.
    """
    def __init__(self, bit_length: int = 2048, key_path: str = "rsa_keys.pkl"):
        """
        Initialize the RSA object.

        Args:
            bit_length (int, optional): Length of the RSA key in bits. Defaults to 2048.
            key_path (str, optional): Path to store keys. Defaults to "rsa_keys.pkl".
        """
        self.bit_length = bit_length
        self.e = 65537
        self.key_path = key_path
        if os.path.exists(self.key_path):
            self.load_keys()
        else:
            self.generate_keys()

    def generate_keys(self) -> None:
        """
        Generate RSA public and private keys.

        Raises:
            Exception: If the chosen e is not coprime with phi(n).
        """
        print("Generating RSA keys...")
        p = self.generate_large_prime()
        q = self.generate_large_prime()
        while q == p:
            q = self.generate_large_prime()

        self.n = p * q
        phi = (p - 1) * (q - 1)

        if self.egcd(self.e, phi)[0] != 1:
            raise Exception("e and phi(n) are not coprime. Choose different primes.")

        self.d = self.modinv(self.e, phi)

        self.public_key = (self.n, self.e)
        self.private_key = (self.n, self.d)

        self.save_keys()
        print("RSA keys generated and saved.")

    def save_keys(self) -> None:
        """
        Save the RSA keys to a file.
        """
        with open(self.key_path, 'wb') as f:
            pickle.dump((self.public_key, self.private_key), f)
        print(f"RSA keys saved to {self.key_path}")

    def load_keys(self) -> None:
        """
        Load RSA keys from a file.
        """
        with open(self.key_path, 'rb') as f:
            self.public_key, self.private_key = pickle.load(f)
        print(f"RSA keys loaded from {self.key_path}")

    def generate_large_prime(self) -> int:
        """
        Generate a large prime number using cryptographically secure random.

        Returns:
            int: A large prime number.
        """
        while True:
            num = secrets.randbits(self.bit_length // 2)
            # Ensure number is odd and has the highest bit set
            num |= (1 << (self.bit_length // 2 - 1)) | 1
            if self.is_prime(num):
                return num

    def is_prime(self, n: int, k: int = 5) -> bool:
        """
        Miller-Rabin primality test to check if a number is prime.

        Args:
            n (int): Number to test for primality.
            k (int, optional): Number of test iterations. Defaults to 5.

        Returns:
            bool: True if n is prime, False otherwise.
        """
        if n <= 3:
            return n == 2 or n == 3
        if n % 2 == 0:
            return False

        r, d = 0, n - 1
        while d % 2 == 0:
            d //= 2
            r += 1

        for _ in range(k):
            a = secrets.randbelow(n - 3) + 2  # a ∈ [2, n-2]
            x = pow(a, d, n)

            if x == 1 or x == n - 1:
                continue

            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def egcd(self, a: int, b: int) -> tuple:
        """
        Extended Euclidean Algorithm.

        Args:
            a (int): First integer.
            b (int): Second integer.

        Returns:
            tuple: (gcd, x, y) such that gcd = a*x + b*y.
        """
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = self.egcd(b % a, a)
            return (g, x - (b // a) * y, y)

    def modinv(self, a: int, m: int) -> int:
        """
        Compute the modular inverse using the Extended Euclidean Algorithm.

        Args:
            a (int): Integer to invert.
            m (int): Modulus.

        Returns:
            int: Modular inverse of a modulo m.

        Raises:
            Exception: If the modular inverse does not exist.
        """
        g, x, _ = self.egcd(a, m)
        if g != 1:
            raise Exception('Modular inverse does not exist.')
        else:
            return x % m

    def encrypt_int(self, plaintext_int: int) -> int:
        """
        Encrypt an integer using the public key.

        Args:
            plaintext_int (int): The integer to encrypt.

        Returns:
            int: The encrypted integer.
        """
        n, e = self.public_key
        return pow(plaintext_int, e, n)

    def decrypt_int(self, ciphertext_int: int) -> int:
        """
        Decrypt an integer using the private key.

        Args:
            ciphertext_int (int): The integer to decrypt.

        Returns:
            int: The decrypted integer.
        """
        n, d = self.private_key
        return pow(ciphertext_int, d, n)
