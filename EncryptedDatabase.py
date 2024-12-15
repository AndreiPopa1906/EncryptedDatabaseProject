import os
import sqlite3
import uuid
from RSA import RSA
from File import File

"""
Encrypted Database Management

This module provides tools for encrypting, storing, retrieving, and managing files
using RSA encryption and a SQLite database. Passphrase authentication ensures private key security.

Classes:
    - KeyManager: Manages passphrase-based authentication for private key access.
    - EncryptedDatabase: Provides file encryption, decryption, and database management.

Example Usage:
    db = EncryptedDatabase()
    db.encrypt_file("example.txt")
    db.list_files()
    db.decrypt_file(file_uuid, output_path="/output")
"""
class KeyManager:
    """
        Handles passphrase-based authentication for RSA private key access.

        Attributes:
            rsa (RSA): RSA object for encryption and decryption.
            _passphrase (str): Private passphrase for key security.
    """
    def __init__(self, rsa):
        """
            Initialize KeyManager with an RSA object.

            Args:
                rsa (RSA): RSA encryption object.
        """
        self.rsa = rsa
        self._passphrase = None

    def set_passphrase(self, passphrase):
        """
        Set a passphrase for private key access.

        Args:
            passphrase (str): Passphrase for key authentication.

        Raises:
            ValueError: If the passphrase is empty.
        """

        if not passphrase:
            raise ValueError("Passphrase cannot be empty.")
        self._passphrase = passphrase
        print("Passphrase has been set successfully.")

    def authenticate(self, passphrase):
        """
        Authenticate user access to the private key.

        Args:
            passphrase (str): Passphrase entered by the user.

        Raises:
            PermissionError: If the passphrase is incorrect or not set.
        """
        try:
            if self._passphrase is None:
                raise PermissionError("Passphrase has not been set. Please set a passphrase first.")
            if passphrase != self._passphrase:
                raise PermissionError("Invalid passphrase. Access denied.")
            print("Authentication successful. Private key access granted.")
        except PermissionError as e:
            raise e

class EncryptedDatabase:
    """
    Manages file encryption, storage, and retrieval using a SQLite database and RSA encryption.

    Attributes:
        db_path (str): Path to the SQLite database file.
        rsa (RSA): RSA object for encryption and decryption.
        key_manager (KeyManager): Manages RSA private key access with a passphrase.
    """

    def __init__(self, db_path="encrypted_files.db", key_size=2048):
        """
        Initialize the EncryptedDatabase.

        Args:
            db_path (str, optional): Path to the SQLite database. Defaults to "encrypted_files.db".
            key_size (int, optional): RSA key size in bits. Defaults to 2048.
        """
        self.db_path = os.path.abspath(db_path)
        print(f"Using database at: {self.db_path}")  # Debug statement
        self.rsa = RSA(bit_length=key_size)  # Uses persisted keys if available
        self.public_key, self.private_key = self.rsa.public_key, self.rsa.private_key
        self.key_manager = KeyManager(self.rsa)
        self.init_database()

    def init_database(self):
        """
        Initialize the SQLite database schema for encrypted file storage.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''CREATE TABLE IF NOT EXISTS files (
                                    id TEXT PRIMARY KEY,
                                    name TEXT NOT NULL,
                                    content BLOB NOT NULL,
                                    metadata BLOB NOT NULL
                                )''')
                conn.commit()
            print("Database initialized with correct schema.")  # Debug statement
        except Exception as e:
            print(f"An error occurred during database initialization: {e}")

    def encrypt_file(self, file_path):
        """
        Encrypt a file and store it in the database.

        Args:
            file_path (str): Path to the file to be encrypted.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError("File does not exist.")

            print(f"Encrypting file: {file_path}")  # Debug statement

            file = File(file_path, self.rsa)
            content = file.get_content()

            # Encrypt content and metadata
            encrypted_content = file.encrypt_content(content)

            metadata_str = f"name:{os.path.basename(file_path)}|size:{len(content)}"
            metadata_bytes = metadata_str.encode('utf-8')
            metadata_int = int.from_bytes(metadata_bytes, byteorder='big')
            encrypted_metadata = self.rsa.encrypt_int(metadata_int)

            # Convert encrypted data to bytes
            encrypted_content_bytes = encrypted_content.to_bytes((encrypted_content.bit_length() + 7) // 8, 'big')
            encrypted_metadata_bytes = encrypted_metadata.to_bytes((encrypted_metadata.bit_length() + 7) // 8, 'big')

            print("Encrypted content and metadata successfully.")  # Debug statement

            # Generate UUID for the file
            file_uuid = str(uuid.uuid4())

            # Insert into database with UUID
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT INTO files (id, name, content, metadata) VALUES (?, ?, ?, ?)',
                               (file_uuid, os.path.basename(file_path), encrypted_content_bytes, encrypted_metadata_bytes))
                conn.commit()

            print(f"File '{file_path}' has been encrypted and stored with UUID: {file_uuid}.")
        except Exception as e:
            print(f"An error occurred during encryption: {e}")

    def decrypt_file(self, file_uuid, output_path=None):
        """
        Decrypt a file and save it to the specified output path, or display its content.

        Args:
            file_uuid (str): UUID of the file to decrypt.
            output_path (str, optional): Path to save the decrypted file. Defaults to None.

        Raises:
            FileNotFoundError: If the file UUID does not exist.
            PermissionError: If authentication fails.
        """
        try:
            passphrase = input("Enter passphrase to access private key: ")
            self.key_manager.authenticate(passphrase)

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT name, content FROM files WHERE id = ?', (file_uuid,))
                result = cursor.fetchone()

            if not result:
                raise FileNotFoundError("File not found in the database.")

            file_name, encrypted_content_bytes = result

            print(f"Decrypting file: {file_name} with UUID: {file_uuid}")

            # Convert encrypted content bytes back to an integer
            encrypted_content = int.from_bytes(encrypted_content_bytes, 'big')

            # Decrypt the content
            file = File(file_name, self.rsa)
            decrypted_content = file.decrypt_content(encrypted_content)

            # Save the decrypted file if an output path is provided
            if output_path:
                if not os.path.isdir(output_path):
                    raise NotADirectoryError(f"Invalid output directory: {output_path}")

                full_output_path = os.path.join(output_path, file_name)
                with open(full_output_path, 'wb') as output_file:
                    output_file.write(decrypted_content)
                print(f"File '{file_name}' has been decrypted and saved to '{full_output_path}'.")
            else:
                # Display the decrypted content
                print("\nDecrypted File Content:")
                print(decrypted_content.decode('utf-8', errors='ignore'))  # Attempt to decode as text
        except PermissionError as pe:
            print(f"Authentication failed: {pe}")
        except Exception as e:
            print(f"An error occurred during decryption: {e}")

    def read_file(self, file_uuid):
        """
        Decrypt a file and display its content in the console.

        Args:
            file_uuid (str): UUID of the file to read(decrypted).

        Raises:
            FileNotFoundError: If the file UUID does not exist.
            PermissionError: If authentication fails.
        """
        try:
            passphrase = input("Enter passphrase to access private key: ")
            self.key_manager.authenticate(passphrase)

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT name, content FROM files WHERE id = ?', (file_uuid,))
                result = cursor.fetchone()

            if not result:
                raise FileNotFoundError("File not found in the database.")

            file_name, encrypted_content_bytes = result

            print(f"Reading file: {file_name} with UUID: {file_uuid}")

            # Convert encrypted content bytes back to an integer
            encrypted_content = int.from_bytes(encrypted_content_bytes, 'big')

            # Decrypt the content
            file = File(file_name, self.rsa)
            decrypted_content = file.decrypt_content(encrypted_content)

            # Display the decrypted content as text
            print("\nDecrypted File Content:")
            print(decrypted_content.decode('utf-8', errors='ignore'))  # Attempt to decode as text
        except PermissionError as pe:
            print(f"Authentication failed: {pe}")
        except Exception as e:
            print(f"An error occurred during file reading: {e}")

    def delete_file(self, file_uuid):
        """
        Delete a file from the database.

        Args:
            file_uuid (str): UUID of the file to delete.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM files WHERE id = ?', (file_uuid,))
                conn.commit()

            print(f"File with UUID '{file_uuid}' has been deleted from the database.")
        except Exception as e:
            print(f"An error occurred during deletion: {e}")

    def list_files(self):
        """
        List all files stored in the database.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT id, name FROM files')
                files = cursor.fetchall()

            if not files:
                print("No files found in the database.")
                return

            print("Files in the database:")
            for file in files:
                print(f"UUID: {file[0]} | Name: {file[1]}")
        except Exception as e:
            print(f"An error occurred while listing files: {e}")

    def view_encrypted_content(self, file_uuid):
        """View the raw encrypted content of a file in the database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT name, content FROM files WHERE id = ?', (file_uuid,))
                result = cursor.fetchone()

            if not result:
                raise FileNotFoundError("File not found in the database.")

            file_name, encrypted_content_bytes = result

            print(f"Encrypted content for file: {file_name} (UUID: {file_uuid})")
            print("Raw Encrypted Content (hex):")
            print(encrypted_content_bytes.hex())  # Display encrypted content as a hex string
        except Exception as e:
            print(f"An error occurred while viewing encrypted content: {e}")


if __name__ == "__main__":
    db = EncryptedDatabase()
    db.init_database()

    while True:
        print("\nOptions:")
        print("1. Encrypt and store a file")
        print("2. Decrypt and retrieve a file")
        print("3. Delete a file")
        print("4. List files")
        print("5. Read a file")
        print("6. Set a passphrase")
        print("7. Exit")
        print("8. View encrypted content (Debug)")

        choice = input("Choose an option: ")

        if choice == "1":
            file_path = input("Enter the path of the file to encrypt: ")
            db.encrypt_file(file_path)
        elif choice == "2":
            db.list_files()
            file_uuid = input("Enter the UUID of the file to decrypt: ")
            output_path = input("Enter the output directory for the decrypted file (leave empty to display content): ")
            db.decrypt_file(file_uuid, output_path if output_path else None)
        elif choice == "3":
            db.list_files()
            file_uuid = input("Enter the UUID of the file to delete: ")
            db.delete_file(file_uuid)
        elif choice == "4":
            db.list_files()
        elif choice == "5":
            db.list_files()
            file_uuid = input("Enter the UUID of the file to read: ")
            db.read_file(file_uuid)
        elif choice == "6":
            new_passphrase = input("Enter a new passphrase: ")
            try:
                db.key_manager.set_passphrase(new_passphrase)
            except ValueError as ve:
                print(f"Error: {ve}")
        elif choice == "7":
            print("Exiting the program.")
            break
        elif choice == "8":
            db.list_files()
            file_uuid = input("Enter the UUID of the file to view encrypted content: ")
            db.view_encrypted_content(file_uuid)
        else:
            print("Invalid option. Please try again.")


