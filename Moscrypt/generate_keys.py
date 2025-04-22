#!/usr/bin/env python
"""
Generate secure keys for Moscrypt

This script generates secure random keys for use in the .env file.
Run this script to generate new keys for a fresh installation.

WARNING: Do not change the MOSCRYPT_MASTER_KEY after you have encrypted data
or you will lose access to all encrypted information!
"""

import os
import base64
from cryptography.fernet import Fernet
import secrets

def generate_flask_secret():
    """Generate a secure random key for Flask sessions"""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8')

def generate_master_key():
    """Generate a Fernet key for master encryption"""
    return Fernet.generate_key().decode('utf-8')

if __name__ == "__main__":
    flask_key = generate_flask_secret()
    master_key = generate_master_key()
    
    print("\n=== Moscrypt Security Keys ===")
    print("\nFlask Secret Key:")
    print(flask_key)
    print("\nMaster Encryption Key:")
    print(master_key)
    
    # Check if .env exists
    if os.path.exists('.env'):
        print("\nNOTICE: A .env file already exists.")
        overwrite = input("Do you want to update it with these new keys? (y/n): ")
        if overwrite.lower() != 'y':
            print("Operation cancelled. Keys NOT saved to .env file.")
            exit(0)
    
    # Create/update the .env file
    try:
        # Read existing .env content if it exists
        env_lines = []
        if os.path.exists('.env'):
            with open('.env', 'r') as f:
                env_lines = f.readlines()
        
        # Process lines, replacing or adding the keys
        flask_line_found = False
        master_line_found = False
        for i, line in enumerate(env_lines):
            if line.startswith('FLASK_SECRET_KEY='):
                env_lines[i] = f'FLASK_SECRET_KEY={flask_key}\n'
                flask_line_found = True
            elif line.startswith('MOSCRYPT_MASTER_KEY='):
                env_lines[i] = f'MOSCRYPT_MASTER_KEY={master_key}\n'
                master_line_found = True
        
        # Add keys if they weren't found
        if not flask_line_found:
            env_lines.append(f'FLASK_SECRET_KEY={flask_key}\n')
        if not master_line_found:
            env_lines.append(f'MOSCRYPT_MASTER_KEY={master_key}\n')
        
        # Write the updated content
        with open('.env', 'w') as f:
            f.writelines(env_lines)
        
        print("\nKeys successfully saved to .env file.")
        print("\nWARNING: Keep your .env file secure and never commit it to version control!")
        print("         Add .env to your .gitignore file.")
        
    except Exception as e:
        print(f"\nError saving keys: {str(e)}")
        print("Please manually update your .env file with the keys shown above.")
    
    print("\n===== IMPORTANT SECURITY NOTICE =====")
    print("If you change the MOSCRYPT_MASTER_KEY after encrypting data,")
    print("you will PERMANENTLY LOSE ACCESS to all encrypted information!")
    print("=====================================\n") 