import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding

# Function to encrypt the dataset 
def encrypt_dataset(file_path, password):
    # Generate a random salt
    salt = os.urandom(16)

    # Derive a key from the password using PBKDF2HMAC
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256-bit key for AES-256
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())  # Derived key from the password

    # Display the derived encryption key
    print("Derived Encryption Key (in hexadecimal format):", key.hex())

    # Generate a random initialization vector
    iv = os.urandom(12)

    # Create the AES-GCM cipher object
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Read the file contents
    with open(file_path, 'rb') as input_file:
        file_data = input_file.read()

    # Pad the file data 
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()

    # Encrypt the file contents
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Save the encrypted data to a new file
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, 'wb') as output_file:
        output_file.write(salt + iv + encryptor.tag + ciphertext)

    print(f"File '{file_path}' encrypted successfully and saved as '{encrypted_file_path}'")

# Example usage
file_path = r"C:\Users\gtmgo\Downloads\iris-dataset-logistic-regression.ipynb"  # File to be encrypted
password = "strongpassword123"

encrypt_dataset(file_path, password)

