from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

# Function to generate a random key using a password and salt
def generate_key(password: str, salt: bytes):
    # Derive a key from a password using PBKDF2 (Password-Based Key Derivation Function)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())  # Derive a key from the password

# Encrypt function
def encrypt(plain_text: str, password: str):
    # Generate a random salt
    salt = os.urandom(16)
    
    # Generate a key based on the password and salt
    key = generate_key(password, salt)
    
    # Generate a random initialization vector (IV)
    iv = os.urandom(16)

    # Pad the plaintext to be AES block size (16 bytes) using PKCS7 padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()

    # Create an AES cipher in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the padded data
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()

    # Encode salt, iv, and cipher_text in a URL-safe format to return
    return urlsafe_b64encode(salt + iv + cipher_text).decode()

# Decrypt function
def decrypt(cipher_text: str, password: str):
    # Decode the cipher_text from URL-safe base64 format
    cipher_text_bytes = urlsafe_b64decode(cipher_text)

    # Extract the salt, IV, and the encrypted message
    salt = cipher_text_bytes[:16]  # First 16 bytes are the salt
    iv = cipher_text_bytes[16:32]  # Next 16 bytes are the IV
    encrypted_message = cipher_text_bytes[32:]  # The rest is the encrypted message

    # Generate the same key using the password and salt
    key = generate_key(password, salt)

    # Create an AES cipher in CBC mode with the same IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the message
    decrypted_padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

    # Unpad the decrypted message
    unpadder = padding.PKCS7(128).unpadder()
    plain_text = unpadder.update(decrypted_padded_message) + unpadder.finalize()

    return plain_text.decode()

# Example usage
if __name__ == "__main__":
    # Take input from the user
    password = input("Enter a password: ")
    message = input("Enter the message to encrypt: ")

    print(f"\nOriginal Message: {message}")

    # Encrypt the message
    encrypted_message = encrypt(message, password)
    print(f"Encrypted Message: {encrypted_message}")

    # Decrypt the message
    decrypted_message = decrypt(encrypted_message, password)
    print(f"Decrypted Message: {decrypted_message}")
