from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib
import os

# Constants
SALT_LENGTH = 16        # Salt length in bytes (16 bytes for PBKDF2)
IV_LENGTH = 16          # AES block size is 16 bytes
KEY_SIZE = 32           # AES-256 key size (256 bits / 8 = 32 bytes)
ITERATIONS = 1000000    # PBKDF2 iterations to make key derivation slower

def generate_salt():
    """Generate a random salt for key derivation"""
    return get_random_bytes(SALT_LENGTH)

def derive_key(passphrase, salt):
    """Derive a secure key using PBKDF2"""
    # Using PBKDF2 to derive a key from the passphrase and salt
    key = PBKDF2(passphrase, salt, dkLen=KEY_SIZE, count=ITERATIONS)
    return key

def encrypt_message(message, passphrase):
    """Encrypt a message using AES-256 and PBKDF2"""
    salt = generate_salt()  # Generate a random salt
    iv = get_random_bytes(IV_LENGTH)  # Generate a random IV for CBC mode
    key = derive_key(passphrase, salt)  # Derive the encryption key

    # Pad the message to be multiple of AES block size (16 bytes)
    padded_message = pad(message.encode(), AES.block_size)

    # Encrypt the message
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_message = cipher.encrypt(padded_message)

    # Return the encrypted message, IV, and salt (all need to be stored for decryption)
    return base64.b64encode(salt + iv + encrypted_message).decode()

def decrypt_message(encrypted_message, passphrase):
    """Decrypt a message using AES-256 and PBKDF2"""
    encrypted_data = base64.b64decode(encrypted_message)

    # Extract the salt, IV, and the actual encrypted message
    salt = encrypted_data[:SALT_LENGTH]
    iv = encrypted_data[SALT_LENGTH:SALT_LENGTH + IV_LENGTH]
    encrypted_message = encrypted_data[SALT_LENGTH + IV_LENGTH:]

    # Derive the key using the passphrase and the extracted salt
    key = derive_key(passphrase, salt)

    # Decrypt the message
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size)

    # Return the decrypted message as a string
    return decrypted_message.decode()

def encrypt_to_file(message, passphrase, file_name):
    """Encrypt a message and save it to a file"""
    encrypted_message = encrypt_message(message, passphrase)
    with open(file_name, 'w') as file:
        file.write(encrypted_message)

def decrypt_from_file(file_name, passphrase):
    """Read an encrypted message from a file and decrypt it"""
    with open(file_name, 'r') as file:
        encrypted_message = file.read()
    return decrypt_message(encrypted_message, passphrase)
