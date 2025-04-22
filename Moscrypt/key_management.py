#!/usr/bin/env python
"""
Key Management Module for Moscrypt

This module provides secure key management functions including:
- Key derivation from master keys
- Key versioning
- Secure key operations
"""
import os
import base64
import hashlib
import logging
from typing import Optional, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
KEY_VERSION = "v1"  # Used for identifying key format in metadata
ITERATION_COUNT = 100000  # PBKDF2 iteration count

class KeyManager:
    """Manages cryptographic keys and operations"""
    
    def __init__(self, master_key: str):
        """Initialize with a master key"""
        if not master_key:
            raise ValueError("Master key cannot be empty")
        
        self.master_key = master_key.encode() if isinstance(master_key, str) else master_key
        self.primary_cipher = Fernet(self.master_key)
    
    @staticmethod
    def generate_key() -> bytes:
        """Generate a new secure random key"""
        return Fernet.generate_key()
    
    @staticmethod
    def derive_key_from_password(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Derive a cryptographic key from a password using PBKDF2
        Returns a tuple of (key, salt)
        """
        if not salt:
            salt = os.urandom(16)
        
        # Use PBKDF2 to derive a key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 32 bytes = 256 bits
            salt=salt,
            iterations=ITERATION_COUNT,
        )
        
        # Derive the key
        key_bytes = kdf.derive(password.encode())
        
        # Convert to Fernet-compatible format (URL-safe base64)
        key = base64.urlsafe_b64encode(key_bytes)
        
        return key, salt
    
    def create_purpose_key(self, purpose: str) -> bytes:
        """
        Derive a purpose-specific key from the master key
        Purpose could be 'user_kek', 'session', etc.
        """
        # Create a unique salt based on the purpose
        purpose_salt = hashlib.sha256(purpose.encode()).digest()[:16]
        
        # Derive a new key for this specific purpose
        purpose_key, _ = self.derive_key_from_password(
            password=self.master_key.decode(), 
            salt=purpose_salt
        )
        
        return purpose_key
    
    def encrypt(self, data: bytes, purpose: Optional[str] = None) -> bytes:
        """
        Encrypt data with either the master key or a purpose-derived key
        """
        if purpose:
            purpose_key = self.create_purpose_key(purpose)
            cipher = Fernet(purpose_key)
            return cipher.encrypt(data)
        
        # Use primary cipher if no purpose specified
        return self.primary_cipher.encrypt(data)
    
    def decrypt(self, encrypted_data: bytes, purpose: Optional[str] = None) -> bytes:
        """
        Decrypt data with either the master key or a purpose-derived key
        """
        if purpose:
            purpose_key = self.create_purpose_key(purpose)
            cipher = Fernet(purpose_key)
            return cipher.decrypt(encrypted_data)
        
        # Use primary cipher if no purpose specified
        return self.primary_cipher.decrypt(encrypted_data)
    
    def wrap_key(self, key_to_wrap: bytes, purpose: str = "key_wrapping") -> bytes:
        """
        Wrap (encrypt) another key using a derived key
        """
        return self.encrypt(key_to_wrap, purpose=purpose)
    
    def unwrap_key(self, wrapped_key: bytes, purpose: str = "key_wrapping") -> bytes:
        """
        Unwrap (decrypt) a wrapped key using a derived key
        """
        return self.decrypt(wrapped_key, purpose=purpose)
    
    @staticmethod
    def format_with_metadata(key: bytes, version: str = KEY_VERSION) -> str:
        """
        Format a key with metadata for storage
        Example format: v1:base64encodedkey
        """
        if isinstance(key, str):
            key = key.encode()
        
        b64_key = base64.urlsafe_b64encode(key).decode()
        return f"{version}:{b64_key}"
    
    @staticmethod
    def parse_with_metadata(formatted_key: str) -> Tuple[str, bytes]:
        """
        Parse a key with metadata
        Returns tuple of (version, key)
        """
        if ":" not in formatted_key:
            # Legacy key without metadata
            return "legacy", formatted_key.encode()
        
        version, b64_key = formatted_key.split(":", 1)
        key = base64.urlsafe_b64decode(b64_key.encode())
        return version, key 