from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# Function to derive a key from a password
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Function to encrypt a file
def encrypt_file(file_path, password):
    # Generate a random salt
    salt = os.urandom(16)
    # Derive the key from the password
    key = derive_key(password, salt)
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)

    # Read the file data
    with open(file_path, "rb") as file:
        plaintext = file.read()

    # Pad the plaintext to match block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # Encrypt the data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Save the encrypted file
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, "wb") as file:
        file.write(salt + iv + ciphertext)

    print(f"[*] File encrypted successfully: {encrypted_file_path}")

# Function to decrypt a file
def decrypt_file(encrypted_file_path, password):
    # Read the encrypted file
    with open(encrypted_file_path, "rb") as file:
        data = file.read()

    # Extract salt, IV, and ciphertext
    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]

    # Derive the key from the password
    key = derive_key(password, salt)

    # Decrypt the data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # Save the decrypted file
    decrypted_file_path = encrypted_file_path[:-4]  # Remove .enc extension
    with open(decrypted_file_path, "wb") as file:
        file.write(plaintext)

    print(f"[*] File decrypted successfully: {decrypted_file_path}")

# Main function
def main():
    print("File Encryption/Decryption Tool")
    choice = input("Choose an option:\n1. Encrypt a file\n2. Decrypt a file\nEnter your choice (1 or 2): ")

    if choice == "1":
        file_path = input("Enter the file path to encrypt: ")
        password = input("Enter a password: ")
        encrypt_file(file_path, password)
    elif choice == "2":
        encrypted_file_path = input("Enter the file path to decrypt: ")
        password = input("Enter the password: ")
        decrypt_file(encrypted_file_path, password)
    else:
        print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
