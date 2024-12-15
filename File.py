# File.py
from RSA import RSA

class File:
    def __init__(self, name, rsa=None):
        self.name = name
        self.rsa = rsa if rsa else RSA(bit_length=2048)

    def get_content(self):
        """Read the file content."""
        with open(self.name, 'rb') as file:
            return file.read()

    def encrypt_content(self, content):
        """Encrypt the given content."""
        # Convert bytes directly to integer without decoding
        plaintext_int = int.from_bytes(content, byteorder='big')
        encrypted_int = self.rsa.encrypt_int(plaintext_int)
        return encrypted_int

    def decrypt_content(self, encrypted_content):
        """Decrypt the given encrypted content."""
        decrypted_int = self.rsa.decrypt_int(encrypted_content)
        # Convert integer back to bytes
        decrypted_bytes = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big')
        return decrypted_bytes
