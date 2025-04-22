#!/usr/bin/env python
"""
Database migration script to update User model with new security fields.
Run this script after updating the application code but before restarting the server.
"""
import bcrypt
import datetime
import logging
import os
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
database_url = os.environ.get('DATABASE_URL')

if not database_url:
    database_url = 'sqlite:///database.db'
    logger.info("Using SQLite database for migration")
elif database_url.startswith('postgres://'):
    # Heroku-style postgres:// URLs need to be updated for SQLAlchemy 1.4+
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

# Set up SQLAlchemy
Base = declarative_base()

# Define a minimal version of the User model with only the fields we need
class User(Base):
    __tablename__ = 'user'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    password_hash = Column(String(120), nullable=False)
    password_salt = Column(String(64), nullable=True)  # Added field
    failed_login_attempts = Column(Integer, default=0)
    last_failed_login = Column(DateTime, nullable=True)
    last_login = Column(DateTime, nullable=True)
    last_password_change = Column(DateTime, nullable=True)
    password_reset_token = Column(String(120), nullable=True)
    password_reset_expiry = Column(DateTime, nullable=True)

def main():
    # Connect to the database
    engine = create_engine(database_url)
    
    # Check if new columns exist
    from sqlalchemy import inspect
    inspector = inspect(engine)
    columns = [column['name'] for column in inspector.get_columns('user')]
    
    # Add missing columns
    missing_columns = []
    
    if 'password_salt' not in columns:
        missing_columns.append(Column('password_salt', String(64), nullable=True))
    
    if 'failed_login_attempts' not in columns:
        missing_columns.append(Column('failed_login_attempts', Integer, default=0))
    
    if 'last_failed_login' not in columns:
        missing_columns.append(Column('last_failed_login', DateTime, nullable=True))
    
    if 'last_login' not in columns:
        missing_columns.append(Column('last_login', DateTime, nullable=True))
    
    if 'last_password_change' not in columns:
        missing_columns.append(Column('last_password_change', DateTime, nullable=True))
    
    if 'password_reset_token' not in columns:
        missing_columns.append(Column('password_reset_token', String(120), nullable=True))
    
    if 'password_reset_expiry' not in columns:
        missing_columns.append(Column('password_reset_expiry', DateTime, nullable=True))
    
    # Add missing columns to the database
    if missing_columns:
        from alembic.migration import MigrationContext
        from alembic.operations import Operations
        
        conn = engine.connect()
        ctx = MigrationContext.configure(conn)
        op = Operations(ctx)
        
        for column in missing_columns:
            try:
                op.add_column('user', column)
                logger.info(f"Added column {column.name} to user table")
            except Exception as e:
                logger.error(f"Error adding column {column.name}: {str(e)}")
        
        conn.close()
    
    # Update existing users with salt
    Session = sessionmaker(bind=engine)
    session = Session()
    
    try:
        users = session.query(User).all()
        now = datetime.datetime.utcnow()
        
        for user in users:
            # Skip users that already have a salt
            if user.password_salt:
                continue
                
            # Extract salt from password hash if possible (bcrypt hash contains the salt)
            # or generate a new one
            try:
                # For bcrypt, we can use the existing hash as it contains the salt
                password_hash = user.password_hash.encode('utf-8')
                user.password_salt = password_hash[:29].decode('utf-8')  # Extract salt portion
            except Exception:
                # If we can't extract the salt, generate a new one and mark for password reset
                salt = bcrypt.gensalt().decode('utf-8')
                user.password_salt = salt
                user.password_reset_token = os.urandom(16).hex()
                user.password_reset_expiry = now + datetime.timedelta(days=1)
                logger.warning(f"Generated new salt for user {user.username} - password reset required")
            
            # Set default values for other missing fields
            if user.failed_login_attempts is None:
                user.failed_login_attempts = 0
            
            if user.last_password_change is None:
                user.last_password_change = now
        
        session.commit()
        logger.info(f"Updated {len(users)} user records with security fields")
    
    except Exception as e:
        session.rollback()
        logger.error(f"Error updating users: {str(e)}")
    finally:
        session.close()

if __name__ == "__main__":
    logger.info("Starting database migration...")
    main()
    logger.info("Database migration completed.") 