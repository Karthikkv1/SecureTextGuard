
# SecureTextGuard

**SecureTextGuard** is a Python-based encryption tool that allows users to securely encrypt and decrypt text messages using the AES encryption algorithm. This ensures that sensitive information is protected and accessible only by those with the correct password.

## Features

- **AES Encryption**: Uses AES (Advanced Encryption Standard) in CBC (Cipher Block Chaining) mode to encrypt messages securely.
- **Password-based Key Generation**: Derives encryption keys from user-provided passwords using PBKDF2 (Password-Based Key Derivation Function 2) with SHA-256.
- **Secure Random Initialization Vectors**: Generates a secure random IV (Initialization Vector) to ensure strong encryption for every message.
- **Interactive User Input**: Allows users to input their own password and message for encryption and decryption.

## How It Works

1. **Encryption**: The user provides a password and a message. A random salt and IV are generated to securely encrypt the message. The resulting ciphertext is encoded using a URL-safe base64 format and displayed to the user.
   
2. **Decryption**: The user provides the password and the encrypted message. Using the same salt and IV, the message is decrypted and the original text is retrieved if the correct password is provided.

## Requirements

- Python 3.6 or above
- cryptography module

## Installation

1. Clone the repository or download the project files.

```bash
git clone https://github.com/Karthikkv1/SecureTextGuard.git
cd SecureTextGuard
```

2. Install the required dependencies using `pip`.

```bash
pip install cryptography
```

## Usage

1. **Run the script:**

   ```bash
   python securetextguard.py
   ```

2. **Input the password and message**:
   - You will be prompted to enter a password.
   - Then, you will be asked to enter the message that you want to encrypt.

3. **View the encrypted message**:
   - The encrypted message will be displayed.

4. **Decrypt the message**:
   - Use the same password to decrypt the message and retrieve the original text.

### Example

```bash
Enter a password: mypassword123
Enter the message to encrypt: Hello, this is a secure message.

Original Message: Hello, this is a secure message.
Encrypted Message: YWwx... (truncated)
Decrypted Message: Hello, this is a secure message.
```

## Project Structure

```plaintext
.
├── securetextguard.py   # Main script for encryption and decryption
├── README.md            # Project documentation
└── LICENSE              # License information
```

## Security Notes

- This tool uses AES encryption with secure key derivation (PBKDF2) and a random IV, making it suitable for protecting sensitive information.
- Ensure that you choose strong passwords to enhance the security of the encrypted data.



Feel free to customize the project name and GitHub URL if needed!
