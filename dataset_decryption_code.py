import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding

# Function to decrypt the dataset (file) and display the derived key
def decrypt_dataset(encrypted_file_path, password):
    # Read the encrypted file contents
    with open(encrypted_file_path, 'rb') as encrypted_file:
        # Extract the salt, IV, and authentication tag from the file
        salt = encrypted_file.read(16)  # First 16 bytes: salt
        iv = encrypted_file.read(12)    # Next 12 bytes: IV
        tag = encrypted_file.read(16)   # Next 16 bytes: authentication tag
        ciphertext = encrypted_file.read()  # Remaining: ciphertext

    # Derive the key from the password using the same PBKDF2HMAC process
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256-bit key for AES-256
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())  # Derive the key from the password

    # Display the derived decryption key (for demonstration)
    print("Derived Decryption Key (in hexadecimal format):", key.hex())

    # Create the AES-GCM cipher object for decryption
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    # Save the decrypted data to a new file (removing ".enc" from the file name)
    original_file_path = encrypted_file_path.replace('.enc', '')
    with open(original_file_path, 'wb') as output_file:
        output_file.write(decrypted_data)

    print(f"File '{encrypted_file_path}' decrypted successfully and saved as '{original_file_path}'")

# Example usage for decryption
encrypted_file_path = r"C:\Users\gtmgo\Downloads\iris-dataset-logistic-regression.ipynb.enc"
password = "strongpassword123"

decrypt_dataset(encrypted_file_path, password)
