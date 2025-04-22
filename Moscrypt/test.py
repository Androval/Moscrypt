'''
This entire page should be useless, but I don't have time to test if it is useless, so just in case I am keeping it here.
'''

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import bcrypt

def generate_keystub():
    """
    Generate a keystub using Elliptic Curve Cryptography (ECC).
    Uses the SECP256K1 curve which is widely used in cryptographic applications.
    
    Returns:
        str: The generated keystub in base64 format
    """
    # Generate a private key using the SECP256K1 curve
    private_key = ec.generate_private_key(
        ec.SECP256K1(),
        backend=default_backend()
    )
    
    # Get the public key
    public_key = private_key.public_key()
    
    # Serialize the public key to bytes
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Convert to base64 for easy display and storage
    keystub = base64.b64encode(public_bytes).decode('utf-8')
    
    # Print the keystub
    print(f"Generated ECC Keystub: {keystub}")
    
    return keystub

def generate_kek(password=None):
    """
    Generate a Key Encryption Key (KEK) using AES-256.
    If a password is provided, it will be used to derive the key.
    If no password is provided, a random key will be generated.
    
    Args:
        password (str, optional): Password to derive the KEK from
    
    Returns:
        tuple: (kek, salt) where:
            - kek: The generated Key Encryption Key in base64 format
            - salt: The salt used in key derivation (if password was provided)
    """
    if password:
        # Generate a random salt
        salt = os.urandom(16)
        
        # Use PBKDF2 to derive a key from the password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=salt,
            iterations=100000,  # Number of iterations for key derivation
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key.decode(), salt
    else:
        # Generate a random key if no password is provided
        key = Fernet.generate_key()
        return key.decode(), None

def print_kek_info(kek, salt=None):
    """
    Print information about the generated KEK.
    
    Args:
        kek (str): The generated KEK in base64 format
        salt (bytes, optional): The salt used in key derivation
    """
    # print("\nKey Encryption Key (KEK) Generated:")
    print(f"KEK: {kek}")
    if salt:
        print(f"Salt: {salt.hex()}")
    # print("\nIMPORTANT: Store these values securely!")
    # print("The KEK can be used to encrypt other keys.")
    # print("If using password-based derivation, you'll need both the KEK and salt to recreate the key.")

def create_key_session(kek1, kek2):
    """
    Create a key session by generating a session key and encrypting it with two KEKs.
    Similar to Kerberos's approach for key distribution.
    
    Args:
        kek1 (str): First KEK in base64 format
        kek2 (str): Second KEK in base64 format
    
    Returns:
        tuple: (encrypted_session_key1, encrypted_session_key2) where:
            - encrypted_session_key1: Session key encrypted with first KEK
            - encrypted_session_key2: Session key encrypted with second KEK
    """
    # Generate a random session key
    session_key = Fernet.generate_key()
    
    # Create Fernet instances for each KEK
    f1 = Fernet(kek1.encode())
    f2 = Fernet(kek2.encode())
    
    # Encrypt the session key with each KEK
    encrypted_key1 = f1.encrypt(session_key)
    encrypted_key2 = f2.encrypt(session_key)
    
    return encrypted_key1, encrypted_key2

def decrypt_session_key(encrypted_key, kek):
    """
    Decrypt a session key using a KEK.
    
    Args:
        encrypted_key (bytes): The encrypted session key
        kek (str): The KEK in base64 format
    
    Returns:
        bytes: The decrypted session key
    """
    f = Fernet(kek.encode())
    return f.decrypt(encrypted_key)

def create_user(username, password):
    """
    Create a user with username and password.
    
    Args:
        username (str): The username for the new user
        password (str): The password to hash and store
    
    Returns:
        tuple: (username, hashed_password) where hashed_password is a bcrypt hash
    """
    # Convert password to bytes and hash it
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    
    return username, hashed_password.decode('utf-8')

if __name__ == "__main__":
    # # Generate two KEKs
    # print("Generating KEK 1...")
    # kek1, salt1 = generate_kek()
    # print_kek_info(kek1, salt1)
    
    # print("\nGenerating KEK 2...")
    # kek2, salt2 = generate_kek()
    # print_kek_info(kek2, salt2)
    
    # # Create a key session
    # print("\nCreating key session...")
    # encrypted_key1, encrypted_key2 = create_key_session(kek1, kek2)
    
    # # Demonstrate decryption
    # print("\nDemonstrating decryption...")
    # session_key1 = decrypt_session_key(encrypted_key1, kek1)
    # session_key2 = decrypt_session_key(encrypted_key2, kek2)
    
    # # Verify both decrypted keys are the same
    # print(f"Session keys match: {session_key1 == session_key2}")

    print(create_user("test", "test"))
