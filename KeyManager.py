import hashlib
import socket
import sqlite3

class KeyManager:
    """
    Handles passphrase-based authentication for RSA private key access.
    Stores passphrases hashed with SHA-256 for each user's IP in a database.

    Attributes:
        rsa (RSA): RSA object for encryption and decryption.
        db_path (str): Path to the SQLite database for storing IPs and hashed passphrases.
    """
    def __init__(self, rsa, db_path="passphrases.db"):
        """
        Initialize KeyManager with an RSA object and database path.

        Args:
            rsa: RSA encryption object.
            db_path (str): Path to the SQLite database file.
        """
        self.rsa = rsa
        self.db_path = db_path
        self._current_ip = self._get_ip_address()
        self._init_database()

    def _init_database(self):
        """Initialize the database for storing IPs and hashed passphrases."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS passphrases (
                                ip_address TEXT PRIMARY KEY,
                                passphrase_hash TEXT NOT NULL
                             )''')
            conn.commit()

    def _hash_passphrase(self, passphrase):
        """
        Hash the passphrase using SHA-256.

        Args:
            passphrase (str): The plaintext passphrase.

        Returns:
            str: The hexadecimal hash of the passphrase.
        """
        return hashlib.sha256(passphrase.encode('utf-8')).hexdigest()

    def _get_ip_address(self):
        """
        Retrieve the user's local IP address.

        Returns:
            str: The user's IP address.
        """
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)

    def set_passphrase(self, passphrase):
        """
        Set and save the hashed passphrase for the user's IP address.

        Args:
            passphrase (str): The plaintext passphrase.

        Raises:
            ValueError: If the passphrase is empty.
        """
        if not passphrase:
            raise ValueError("Passphrase cannot be empty.")

        hashed_passphrase = self._hash_passphrase(passphrase)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('REPLACE INTO passphrases (ip_address, passphrase_hash) VALUES (?, ?)',
                           (self._current_ip, hashed_passphrase))
            conn.commit()

        print(f"Passphrase has been set successfully for IP: {self._current_ip}.")

    def authenticate(self, passphrase):
        """
        Authenticate the user by validating their passphrase against the stored hash.

        Args:
            passphrase (str): The plaintext passphrase to validate.

        Raises:
            PermissionError: If the passphrase is incorrect or no passphrase is set for the IP.
        """
        hashed_passphrase = self._hash_passphrase(passphrase)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT passphrase_hash FROM passphrases WHERE ip_address = ?',
                           (self._current_ip,))
            result = cursor.fetchone()

        if not result:
            raise PermissionError(f"No passphrase set for IP: {self._current_ip}. Please set a passphrase first.")

        if hashed_passphrase != result[0]:
            raise PermissionError("Invalid passphrase. Access denied.")

        print("Authentication successful. Private key access granted.")

    def is_passphrase_set(self):
        """
        Check if a passphrase is set for the current user's IP address.

        Returns:
            bool: True if a passphrase exists, False otherwise.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT passphrase_hash FROM passphrases WHERE ip_address = ?',
                           (self._current_ip,))
            result = cursor.fetchone()
        return result is not None
