import os
import sqlite3
import uuid
from RSA import RSA
from File import File
from KeyManager import KeyManager

"""
Encrypted Database Management

This module provides tools for encrypting, storing, retrieving, and managing files
using RSA encryption and a SQLite database. Passphrase authentication ensures private key security.

Classes:
    - EncryptedDatabase: Provides file encryption, decryption, and database management.
"""
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
        print(f"Using database at: {self.db_path}")
        self.rsa = RSA(bit_length=key_size)
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
            print("Database initialized with correct schema.")
        except Exception as e:
            print(f"An error occurred during database initialization: {e}")

    def encrypt_file(self, file_path):
        """
        Encrypt a file and store it on disk, with its metadata saved in the database.

        Args:
            file_path (str): Path to the file that needs to be encrypted.

        Raises:
            FileNotFoundError: If the provided file does not exist.
            Exception: For any errors encountered during the encryption process.

        """
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError("File does not exist.")

            print(f"Encrypting file: {file_path}")

            # Read file content
            file = File(file_path, self.rsa)
            content = file.get_content()

            # Encrypt file content
            encrypted_content = file.encrypt_content(content)
            encrypted_content_bytes = encrypted_content.to_bytes(
                (encrypted_content.bit_length() + 7) // 8, 'big'
            )

            # Save encrypted file to disk
            encrypted_folder = "encrypted_files"
            os.makedirs(encrypted_folder, exist_ok=True)
            encrypted_file_path = os.path.join(
                encrypted_folder, os.path.basename(file_path) + ".enc"
            )

            with open(encrypted_file_path, 'wb') as enc_file:
                enc_file.write(encrypted_content_bytes)

            # Prepare and encrypt metadata
            metadata_str = f"path:{encrypted_file_path}|size:{len(content)}"
            metadata_bytes = metadata_str.encode('utf-8')
            metadata_int = int.from_bytes(metadata_bytes, 'big')
            encrypted_metadata = self.rsa.encrypt_int(metadata_int)
            encrypted_metadata_bytes = encrypted_metadata.to_bytes(
                (encrypted_metadata.bit_length() + 7) // 8, 'big'
            )

            # Generate UUID and store in the database
            file_uuid = str(uuid.uuid4())

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT INTO files (id, name, content, metadata) VALUES (?, ?, ?, ?)',
                    (file_uuid, os.path.basename(file_path),
                     encrypted_file_path, encrypted_metadata_bytes)
                )
                conn.commit()

            print(f"File '{file_path}' has been encrypted and stored at '{encrypted_file_path}'.")

        except Exception as e:
            print(f"An error occurred during encryption: {e}")

    def decrypt_file(self, file_uuid, output_path=None):
        """
        Decrypt a file stored on disk and either save it or display its content.

        Args:
            file_uuid (str): The UUID of the file to be decrypted.
            output_path (str, optional): Directory where the decrypted file will be saved.
                                         If not provided, the content will be displayed.

        Raises:
            PermissionError: If the passphrase authentication fails.
            FileNotFoundError: If the file is not found in the database or on disk.
            NotADirectoryError: If the provided output path is invalid.
            Exception: For any errors encountered during the decryption process.
        """
        try:
            # Authenticate user with passphrase
            passphrase = input("Enter passphrase to access private key: ")
            self.key_manager.authenticate(passphrase)

            # Retrieve file record from database
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'SELECT name, content, metadata FROM files WHERE id = ?', (file_uuid,)
                )
                result = cursor.fetchone()

            if not result:
                raise FileNotFoundError("File not found in the database.")

            file_name, encrypted_file_path, encrypted_metadata_bytes = result

            print(f"Decrypting file: {file_name} with UUID: {file_uuid}")
            print(f"Encrypted file path: {encrypted_file_path}")

            # Verify encrypted file exists on disk
            if not os.path.exists(encrypted_file_path):
                raise FileNotFoundError("Encrypted file not found on disk.")

            # Read encrypted content from disk
            with open(encrypted_file_path, 'rb') as enc_file:
                encrypted_content_bytes = enc_file.read()

            # Convert bytes to integer for RSA decryption
            encrypted_content = int.from_bytes(encrypted_content_bytes, 'big')

            # Decrypt content using RSA
            file = File(file_name, self.rsa)
            decrypted_content = file.decrypt_content(encrypted_content)

            # Save or display the decrypted content
            if output_path:
                if not os.path.isdir(output_path):
                    raise NotADirectoryError(f"Invalid output directory: {output_path}")

                full_output_path = os.path.join(output_path, file_name)

                with open(full_output_path, 'wb') as output_file:
                    output_file.write(decrypted_content)

                print(f"File '{file_name}' has been decrypted and saved to '{full_output_path}'.")
            else:
                print("\nDecrypted File Content:")
                print(decrypted_content.decode('utf-8', errors='ignore'))

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

        # Ensure passphrase is set for the current IP
        if choice in ["2", "5"] and not db.key_manager.is_passphrase_set():
            print("No passphrase found for your IP. Please set a passphrase first.")
            new_passphrase = input("Enter a new passphrase: ")
            db.key_manager.set_passphrase(new_passphrase)

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
            db.key_manager.set_passphrase(new_passphrase)
        elif choice == "7":
            print("Exiting the program.")
            break
        elif choice == "8":
            db.list_files()
            file_uuid = input("Enter the UUID of the file to view encrypted content: ")
            db.view_encrypted_content(file_uuid)
        else:
            print("Invalid option. Please try again.")




