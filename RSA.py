# RSA.py
import secrets
import os
import pickle

class RSA:
    def __init__(self, bit_length=2048, key_path="rsa_keys.pkl"):
        self.bit_length = bit_length
        self.e = 65537
        self.key_path = key_path
        if os.path.exists(self.key_path):
            self.load_keys()
        else:
            self.generate_keys()

    def generate_keys(self):
        """Generate public and private keys."""
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

        return (self.public_key, self.private_key)

    def save_keys(self):
        """Save keys to a file."""
        with open(self.key_path, 'wb') as f:
            pickle.dump((self.public_key, self.private_key), f)
        print(f"RSA keys saved to {self.key_path}")

    def load_keys(self):
        """Load keys from a file."""
        with open(self.key_path, 'rb') as f:
            self.public_key, self.private_key = pickle.load(f)
        print(f"RSA keys loaded from {self.key_path}")

    def generate_large_prime(self):
        """Generate a large prime number using cryptographically secure random."""
        while True:
            num = secrets.randbits(self.bit_length // 2)
            # number is odd and has the highest bit set
            num |= (1 << (self.bit_length // 2 - 1)) | 1
            if self.is_prime(num):
                return num

    def is_prime(self, n, k=5):
        """Miller-Rabin primality test."""
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

    def egcd(self, a, b):
        """Extended Euclidean Algorithm."""
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = self.egcd(b % a, a)
            return (g, x - (b // a) * y, y)

    def modinv(self, a, m):
        """Modular inverse using the Extended Euclidean Algorithm."""
        g, x, _ = self.egcd(a, m)
        if g != 1:
            raise Exception('Modular inverse does not exist.')
        else:
            return x % m

    def encrypt_int(self, plaintext_int):
        """Encrypt an integer using the public key."""
        n, e = self.public_key
        return pow(plaintext_int, e, n)

    def decrypt_int(self, ciphertext_int):
        """Decrypt an integer using the private key."""
        n, d = self.private_key
        return pow(ciphertext_int, d, n)
