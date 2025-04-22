#!/usr/bin/env python
"""
Database migration script to add key_version fields to all relevant tables.
This script should be run before implementing key rotation.
"""
import os
import sys
import logging
from sqlalchemy import Column, String
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
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

def add_version_columns():
    """Add key_version columns to all tables that contain encrypted data"""
    
    # Connect to the database
    engine = create_engine(database_url)
    
    # Check existing columns
    from sqlalchemy import inspect
    inspector = inspect(engine)
    
    # Tables that need the key_version column
    tables_to_update = [
        'user',
        'key',
        'key_session',
        'session_participant',
        'session_message',
        'session_file'
    ]
    
    # Connect with alembic
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    
    conn = engine.connect()
    ctx = MigrationContext.configure(conn)
    op = Operations(ctx)
    
    # Add key_version column to each table if it doesn't exist
    for table in tables_to_update:
        columns = [column['name'] for column in inspector.get_columns(table)]
        
        if 'key_version' not in columns:
            try:
                op.add_column(
                    table,
                    Column('key_version', String(10), server_default="v1")
                )
                logger.info(f"Added key_version column to {table} table")
            except Exception as e:
                logger.error(f"Error adding key_version to {table}: {str(e)}")
    
    conn.close()
    logger.info("Database schema updated for key rotation support")

def main():
    try:
        logger.info("Starting key version migration")
        add_version_columns()
        logger.info("Key version migration completed successfully")
    except Exception as e:
        logger.error(f"Error during migration: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 