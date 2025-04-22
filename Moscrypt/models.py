from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet, InvalidToken
import os
import logging
import datetime
import base64
from key_management import KeyManager
from dotenv import load_dotenv

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    password_salt = db.Column(db.String(64), nullable=False)  # Store individual salt for each user
    kek = db.Column(db.String(120), nullable=True)  # Changed to nullable
    kek_version = db.Column(db.String(10), default="v1")  # Track key version for rotation
    role = db.Column(db.String(20), nullable=False, default='user')
    is_kek_revoked = db.Column(db.Boolean, default=False)  # New field
    keys = db.relationship('Key', backref='user', lazy=True, cascade="all, delete-orphan")
    # Add relationships for key sessions
    created_sessions = db.relationship('KeySession', backref='creator', lazy=True, foreign_keys='KeySession.creator_id')
    participating_sessions = db.relationship('SessionParticipant', backref='user', lazy=True)
    
    # Security-related fields
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_failed_login = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    last_password_change = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    password_reset_token = db.Column(db.String(120), nullable=True)
    password_reset_expiry = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"<User {self.username}>"

class Key(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key_name = db.Column(db.String(50), nullable=False)
    encrypted_key = db.Column(db.LargeBinary, nullable=False)
    key_version = db.Column(db.String(10), default="v1")  # Track key version for rotation
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def __repr__(self):
        return f"<Key {self.key_name}>"

class KeySession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    session_key = db.Column(db.LargeBinary, nullable=False)  # Encrypted with MASTER_KEY
    key_version = db.Column(db.String(10), default="v1")  # Track key version for rotation
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    participants = db.relationship('SessionParticipant', backref='session', lazy=True, cascade="all, delete-orphan")
    is_active = db.Column(db.Boolean, default=True)
    messages = db.relationship('SessionMessage', backref='session', lazy=True, cascade="all, delete-orphan")
    files = db.relationship('SessionFile', backref='session', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<KeySession {self.name}>"

class SessionParticipant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('key_session.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_session_key = db.Column(db.LargeBinary, nullable=False)  # Encrypted with participant's KEK
    key_version = db.Column(db.String(10), default="v1")  # Track key version for rotation
    joined_at = db.Column(db.DateTime, server_default=db.func.now())

    def __repr__(self):
        return f"<SessionParticipant session={self.session_id} user={self.user_id}>"

class SessionMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('key_session.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_content = db.Column(db.LargeBinary, nullable=False)  # Encrypted with session key
    key_version = db.Column(db.String(10), default="v1")  # Track key version for rotation
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    
    sender = db.relationship('User', backref='sent_messages', lazy=True)

    def __repr__(self):
        return f"<SessionMessage session={self.session_id} sender={self.sender_id}>"

class SessionFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('key_session.id'), nullable=False)
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    encrypted_file = db.Column(db.LargeBinary, nullable=False)  # Encrypted with session key
    key_version = db.Column(db.String(10), default="v1")  # Track key version for rotation
    uploaded_at = db.Column(db.DateTime, server_default=db.func.now())
    
    uploader = db.relationship('User', backref='uploaded_files', lazy=True)

    def __repr__(self):
        return f"<SessionFile {self.filename} session={self.session_id}>"

# Initialize key manager with master key
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(dotenv_path)
MASTER_KEY = os.environ.get('MOSCRYPT_MASTER_KEY')
if MASTER_KEY:
    # Convert from string format if stored as base64 text in .env
    if not isinstance(MASTER_KEY, bytes):
        MASTER_KEY = MASTER_KEY.encode('utf-8')
else:
    # This is a fallback for development only, generates new key on restart
    MASTER_KEY = Fernet.generate_key()
    logging.warning(
        "WARNING: Using generated MASTER_KEY. "
        "Set MOSCRYPT_MASTER_KEY environment variable in production "
        "or all encrypted data will be lost on restart!"
    )

try:
    # Initialize key manager
    key_manager = KeyManager(MASTER_KEY)
    # For backward compatibility, maintain the cipher instance
    cipher = Fernet(MASTER_KEY)
except Exception as e:
    logging.error(f"Failed to initialize key manager: {e}")
    raise

def encrypt_key(plaintext_key):
    """Encrypt a key with the purpose-specific derived key"""
    try:
        return key_manager.encrypt(plaintext_key.encode(), purpose="key_encryption")
    except Exception as e:
        logging.error(f"Key encryption error: {e}")
        # Fallback to old method
        return cipher.encrypt(plaintext_key.encode())

def decrypt_key(encrypted_key):
    """Decrypt a key with the appropriate key based on version"""
    try:
        # First try with purpose-specific key
        return key_manager.decrypt(encrypted_key, purpose="key_encryption").decode()
    except InvalidToken:
        # Fallback to original master key for backwards compatibility
        try:
            return cipher.decrypt(encrypted_key).decode()
        except Exception as e:
            logging.error(f"Key decryption error: {e}")
            raise

def create_session_key():
    """Generate a new random session key"""
    return key_manager.generate_key()

def encrypt_session_key(session_key, user_kek):
    """Encrypt session key with user's KEK"""
    try:
        user_cipher = Fernet(user_kek.encode() if isinstance(user_kek, str) else user_kek)
        return user_cipher.encrypt(session_key)
    except Exception as e:
        logging.error(f"Session key encryption error: {e}")
        raise

def encrypt_message(message, session_key):
    """Encrypt a message with the session key"""
    try:
        session_cipher = Fernet(session_key)
        return session_cipher.encrypt(message.encode())
    except Exception as e:
        logging.error(f"Message encryption error: {e}")
        raise

def decrypt_message(encrypted_message, session_key):
    """Decrypt a message with the session key"""
    try:
        session_cipher = Fernet(session_key)
        return session_cipher.decrypt(encrypted_message).decode()
    except Exception as e:
        logging.error(f"Message decryption error: {e}")
        raise

def encrypt_file(file_data, session_key):
    """Encrypt a file with the session key"""
    try:
        session_cipher = Fernet(session_key)
        return session_cipher.encrypt(file_data)
    except Exception as e:
        logging.error(f"File encryption error: {e}")
        raise

def decrypt_file(encrypted_file, session_key):
    """Decrypt a file with the session key"""
    try:
        session_cipher = Fernet(session_key)
        return session_cipher.decrypt(encrypted_file)
    except Exception as e:
        logging.error(f"File decryption error: {e}")
        raise