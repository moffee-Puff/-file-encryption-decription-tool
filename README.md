# File Encryption/Decryption Tool

A simple Python-based tool to encrypt and decrypt files using symmetric encryption (AES-256). Built for Kali Linux, this tool ensures your files are securely encrypted and can only be decrypted with the correct password.

---

## How It Works

The tool uses the `cryptography` library to perform file encryption and decryption. Here's how it works:

1. **Encryption**:
   - The tool takes a file and a password as input.
   - It generates a cryptographic key from the password using a key derivation function (PBKDF2HMAC).
   - The file is encrypted using the AES-256 algorithm in CBC mode.
   - The encrypted file is saved with a `.enc` extension.

2. **Decryption**:
   - The tool takes an encrypted file and the same password used for encryption.
   - It derives the cryptographic key from the password.
   - The file is decrypted using the AES-256 algorithm.
   - The decrypted file is saved with the original filename.

---

## How to Use

### Prerequisites
- Kali Linux (or any Linux distribution with Python 3).
- Python 3.x.
- The `cryptography` library (install using `pip`).

### Installation

1. **Install Cryptography Library**:
   ```bash
   sudo apt update
   sudo apt install python3-pip
   pip3 install cryptography

  2. **Clone the Repository**:
     ```bash
     git clone https://github.com/yourusername/file-encryption-tool.git
     cd file-encryption-tool

  3. **Run the Script**:
     ```bash
     python3 file_crypto.py

   Usage
Encrypt a File
Run the script:

**   python3 file_crypto.py
**
2.Choose the encrypt option.

3.Enter the path to the file you want to encrypt.

4.Enter a strong password (remember this password for decryption).

5.The encrypted file will be saved as filename.enc.

Decrypt a File
Run the script:

**python3 file_crypto.py
**
Choose the Decrypt option.

Enter the path to the encrypted file (e.g., filename.enc).

Enter the password used during encryption.

The decrypted file will be saved with the original filename.

Example Workflow
 ```bash
   $ python3 file_crypto.py
Choose an option:
1. Encrypt a file
2. Decrypt a file
Enter your choice (1 or 2): 1

Enter the file path to encrypt: secret.txt
Enter a password: MyStrongPassword123
[*] File encrypted successfully: secret.txt.enc

$ python3 file_crypto.py
Choose an option:
1. Encrypt a file
2. Decrypt a file
Enter your choice (1 or 2): 2

Enter the file path to decrypt: secret.txt.enc
Enter the password: MyStrongPassword123
[*] File decrypted successfully: secret.txt



