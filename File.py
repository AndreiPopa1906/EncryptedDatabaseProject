"""
File Encryption Module

This module provides functionality for reading, encrypting, and decrypting file content using RSA encryption.

Classes:
    - File: Handles file reading, encryption, and decryption.

Example Usage:
    rsa = RSA(bit_length=2048)
    file = File("example.txt", rsa)
    encrypted_content = file.encrypt_content(file.get_content())
    decrypted_content = file.decrypt_content(encrypted_content)
"""

from RSA import RSA

class File:
    """
    File class for reading, encrypting, and decrypting file content.

    Attributes:
        name (str): Name of the file.
        rsa (RSA): RSA encryption object for encryption and decryption.
    """

    def __init__(self, name: str, rsa: RSA = None):
        """
        Initialize the File object.

        Args:
            name (str): The name of the file to be processed.
            rsa (RSA, optional): RSA instance for encryption. Defaults to None.
        """
        self.name = name
        self.rsa = rsa if rsa else RSA(bit_length=2048)

    def get_content(self) -> bytes:
        """
        Read the file content.

        Returns:
            bytes: Content of the file as bytes.
        """
        with open(self.name, 'rb') as file:
            return file.read()

    def encrypt_content(self, content: bytes) -> int:
        """
        Encrypt the given content.

        Args:
            content (bytes): File content to encrypt.

        Returns:
            int: Encrypted content as an integer.
        """
        plaintext_int = int.from_bytes(content, byteorder='big')
        encrypted_int = self.rsa.encrypt_int(plaintext_int)
        return encrypted_int

    def decrypt_content(self, encrypted_content: int) -> bytes:
        """
        Decrypt the given encrypted content.

        Args:
            encrypted_content (int): Encrypted content to decrypt.

        Returns:
            bytes: Decrypted content as bytes.
        """
        decrypted_int = self.rsa.decrypt_int(encrypted_content)
        decrypted_bytes = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big')
        return decrypted_bytes