import os
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

class Config:
    # Makes a random key if there is no .env file.
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY') or os.urandom(32)
    
    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    
    # If no DATABASE_URL is provided, fall back to SQLite, useful when you don't want to set up the database server
    if not SQLALCHEMY_DATABASE_URI:
        SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db'
        print("WARNING: Using SQLite database. For production, set DATABASE_URL environment variable.")
    elif SQLALCHEMY_DATABASE_URI.startswith('postgres://'):
        # Heroku-style postgres:// URLs need to be updated for SQLAlchemy 1.4+
        SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI.replace('postgres://', 'postgresql://', 1)
        
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # HTTPS settings
    FORCE_HTTPS = os.environ.get('FORCE_HTTPS', 'False').lower() in ('true', '1', 't')
    
    # Session cookie security
    SESSION_COOKIE_SECURE = FORCE_HTTPS
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SECURE = FORCE_HTTPS
    REMEMBER_COOKIE_HTTPONLY = True