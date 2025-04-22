#!/usr/bin/env python
"""
Key Rotation Utility for Moscrypt

This script handles the secure rotation of the master encryption key.
It re-encrypts all sensitive data with the new key while maintaining
access to previously encrypted data.
"""
import os
import sys
import logging
import datetime
import argparse
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('key_rotation.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def load_environment():
    """Load environment variables and database connection"""
    load_dotenv()
    
    # Get current master key
    current_master_key = os.environ.get('MOSCRYPT_MASTER_KEY')
    if not current_master_key:
        logger.error("MOSCRYPT_MASTER_KEY not found in environment variables")
        sys.exit(1)
    
    # Get database URL
    database_url = os.environ.get('DATABASE_URL')
    if not database_url:
        database_url = 'sqlite:///database.db'
        logger.info("Using SQLite database")
    elif database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    
    logger.info("Environment loaded successfully")
    return current_master_key, database_url

def create_backup_env(current_master_key):
    """Create a backup of the current .env file with timestamp"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    backup_file = f".env.backup.{timestamp}"
    
    try:
        with open(".env", "r") as source:
            with open(backup_file, "w") as target:
                for line in source:
                    target.write(line)
        logger.info(f"Created backup of .env file: {backup_file}")
        return backup_file
    except Exception as e:
        logger.error(f"Failed to create backup: {str(e)}")
        sys.exit(1)

def generate_new_key():
    """Generate a new Fernet key"""
    return Fernet.generate_key()

def update_env_file(new_key):
    """Update the .env file with the new master key"""
    try:
        env_content = []
        with open(".env", "r") as f:
            for line in f:
                if line.startswith("MOSCRYPT_MASTER_KEY="):
                    env_content.append(f"MOSCRYPT_MASTER_KEY={new_key.decode()}\n")
                    # Add a history entry
                    env_content.append(f"# Key rotated on {datetime.datetime.now().isoformat()}\n")
                else:
                    env_content.append(line)
        
        with open(".env", "w") as f:
            f.writelines(env_content)
        
        logger.info("Updated .env file with new master key")
    except Exception as e:
        logger.error(f"Failed to update .env file: {str(e)}")
        sys.exit(1)

def reencrypt_keys(database_url, current_master_key, new_key):
    """Re-encrypt all keys in the database with the new master key"""
    from models import Key, KeySession, SessionParticipant
    
    # Set up database connection
    engine = create_engine(database_url)
    Session = sessionmaker(bind=engine)
    session = Session()
    
    # Create Fernet instances with old and new keys
    old_cipher = Fernet(current_master_key.encode() if isinstance(current_master_key, str) else current_master_key)
    new_cipher = Fernet(new_key)
    
    try:
        # Re-encrypt user keys
        keys = session.query(Key).all()
        for key in keys:
            # Decrypt with old key and encrypt with new key
            decrypted_key = old_cipher.decrypt(key.encrypted_key)
            key.encrypted_key = new_cipher.encrypt(decrypted_key)
        
        # Re-encrypt session keys
        key_sessions = session.query(KeySession).all()
        for ks in key_sessions:
            # Decrypt with old key and encrypt with new key
            decrypted_session_key = old_cipher.decrypt(ks.session_key)
            ks.session_key = new_cipher.encrypt(decrypted_session_key)
        
        # Commit changes
        session.commit()
        logger.info(f"Re-encrypted {len(keys)} user keys and {len(key_sessions)} session keys")
    except Exception as e:
        session.rollback()
        logger.error(f"Failed to re-encrypt keys: {str(e)}")
        sys.exit(1)
    finally:
        session.close()

def reencrypt_files(current_master_key, new_key):
    """Re-encrypt files if they use the master key directly"""
    # Implement if needed - currently files are encrypted with session keys,
    # which are already being re-encrypted in reencrypt_keys function
    pass

def main():
    parser = argparse.ArgumentParser(description="Rotate the master encryption key for Moscrypt")
    parser.add_argument("--force", action="store_true", help="Force key rotation without confirmation")
    parser.add_argument("--dry-run", action="store_true", help="Perform a dry run without making changes")
    args = parser.parse_args()
    
    logger.info("Starting key rotation process")
    
    # Load current environment
    current_master_key, database_url = load_environment()
    
    # Warning
    if not args.force:
        print("\n" + "!"*80)
        print("WARNING: You are about to rotate the master encryption key.")
        print("This is a critical operation that affects all encrypted data.")
        print("Make sure you have a backup of your database before proceeding.")
        print("!"*80 + "\n")
        
        confirm = input("Are you sure you want to proceed? (yes/no): ")
        if confirm.lower() != "yes":
            print("Key rotation aborted.")
            sys.exit(0)
    
    # Create backup of .env file
    backup_file = create_backup_env(current_master_key)
    
    # Generate new key
    new_key = generate_new_key()
    logger.info("Generated new master key")
    
    if args.dry_run:
        logger.info("Dry run completed. New key generated but no changes made.")
        print(f"New key (not applied): {new_key.decode()}")
        sys.exit(0)
    
    # Re-encrypt all sensitive data with new key
    reencrypt_keys(database_url, current_master_key, new_key)
    
    # Update .env file with new key
    update_env_file(new_key)
    
    # Final message
    logger.info("Key rotation completed successfully")
    print("\n" + "="*80)
    print("Master key rotation completed successfully!")
    print(f"Backup of previous environment saved to: {backup_file}")
    print("="*80 + "\n")

if __name__ == "__main__":
    main() 