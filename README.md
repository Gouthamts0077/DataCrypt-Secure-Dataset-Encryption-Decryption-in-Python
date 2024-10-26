# Secure Dataset Encryption and Decryption Scripts

This repository contains Python scripts to **encrypt** and **decrypt** dataset files securely using **AES-GCM (Advanced Encryption Standard - Galois/Counter Mode)**. AES-GCM provides both encryption and authentication, making it ideal for securely storing or sharing sensitive data while ensuring data integrity.

## Table of Contents
- [Features](#features)
- [Getting Started](#getting-started)
- [Usage](#usage)
  - [Encrypting a File](#encrypting-a-file)
  - [Decrypting a File](#decrypting-a-file)
- [Arguments](#arguments)
- [Security Considerations](#security-considerations)
- [Example Workflow](#example-workflow)
- [Development](#development)
  - [Code Style and Testing](#code-style-and-testing)
  - [Future Enhancements](#future-enhancements)
- [License](#license)
- [Contributing](#contributing)
- [Acknowledgments](#acknowledgments)

## Features
- **AES-256 Encryption**: Utilizes a strong 256-bit key with AES in GCM mode for encryption and authentication.
- **Secure Key Derivation**: Uses PBKDF2 with SHA-256 hashing, random salt, and 100,000 iterations to securely derive the encryption key from a password.
- **Data Integrity and Authentication**: GCM mode generates an authentication tag that detects unauthorized modifications to encrypted data.
- **Cross-Platform Compatibility**: Works on Windows, macOS, and Linux.

## Getting Started

### Prerequisites
- **Python 3.6+**: Ensure Python is installed. [Download Python](https://www.python.org/downloads/).
- **Cryptography Library**: Install the required `cryptography` package via pip:
  ```bash
  pip install cryptography
Repository Files

    encrypt_dataset.py: Script to encrypt a dataset file.
    decrypt_dataset.py: Script to decrypt an encrypted dataset file.

Setup

Clone the repository:

git clone https://github.com/yourusername/repository-name.git
cd repository-name

Usage
1. Encrypting a File

The encrypt_dataset.py script encrypts a specified file using a password and saves the encrypted data with a .enc extension. Note: Use a strong password for enhanced security.

Command:

python encrypt_dataset.py --file_path "path/to/your/file.txt" --password "yourpassword"

Example:

python encrypt_dataset.py --file_path "C:\Users\username\Documents\data.csv" --password "strongpassword123"

The script performs the following:

    Derives an AES-256 encryption key from the password and a unique salt.
    Encrypts the file data using AES-GCM mode.
    Saves the encrypted file as data.csv.enc in the same directory, containing:
        The salt (16 bytes)
        The IV (12 bytes)
        The authentication tag (16 bytes)
        The ciphertext

2. Decrypting a File

The decrypt_dataset.py script decrypts a previously encrypted file using the same password, restoring the original file format.

Command:

python decrypt_dataset.py --file_path "path/to/your/file.txt.enc" --password "yourpassword"

Example:

python decrypt_dataset.py --file_path "C:\Users\username\Documents\data.csv.enc" --password "strongpassword123"

The decryption script:

    Derives the decryption key using the password and stored salt.
    Decrypts the ciphertext and removes padding.
    Saves the decrypted file as data.csv.

Arguments

The following arguments are accepted by both scripts:

    --file_path: Path to the file you want to encrypt or decrypt (e.g., C:\path\to\file.txt).
    --password: Password for encryption or decryption. Use a strong, unique password.

Security Considerations

    Password Security: Avoid hardcoding passwords directly in the script. Store passwords securely (e.g., use environment variables).
    Environment Variables: Consider using environment variables or secure prompts for sensitive data to avoid exposing passwords.
    Authentication: AES-GCM provides data integrity via an authentication tag. The decryption script will raise an error if the data was altered or if the password is incorrect.
    Backup Encrypted Files: Always keep backup copies of your encrypted files and remember your password, as lost passwords cannot be recovered.

Example Workflow

    Encrypting: Run the encrypt_dataset.py script with a specified file path and password.
    Securely Share Encrypted Data: Share the encrypted .enc file with collaborators.
    Password Sharing: Use a secure method (e.g., encrypted messaging) to share the password.
    Decrypting: Collaborators can use the decrypt_dataset.py script with the encrypted file and password to restore the original data.

Development
Code Style and Testing

    Linting: Maintain code consistency with linting tools like flake8 or black.
    Testing: Add unit tests to validate encryption and decryption functions, especially for edge cases (e.g., invalid password, corrupt data).
