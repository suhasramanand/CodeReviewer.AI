#!/usr/bin/env python3
"""
Clean code example to test that good code passes the review bot.
This file follows best practices and should not trigger any critical issues.
"""

import os
import sqlite3
from typing import List, Dict, Optional
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DatabaseManager:
    """Secure database manager with proper error handling."""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.connection = None
    
    def connect(self) -> bool:
        """Establish database connection with error handling."""
        try:
            self.connection = sqlite3.connect(self.db_path)
            logger.info(f"Connected to database: {self.db_path}")
            return True
        except sqlite3.Error as e:
            logger.error(f"Database connection failed: {e}")
            return False
    
    def execute_query(self, query: str, params: tuple = ()) -> List[Dict]:
        """Execute parameterized query safely."""
        if not self.connection:
            raise ValueError("Database not connected")
        
        try:
            cursor = self.connection.cursor()
            cursor.execute(query, params)  # Safe parameterized query
            results = cursor.fetchall()
            
            # Convert to list of dictionaries
            columns = [description[0] for description in cursor.description]
            return [dict(zip(columns, row)) for row in results]
            
        except sqlite3.Error as e:
            logger.error(f"Query execution failed: {e}")
            raise
    
    def close(self):
        """Close database connection."""
        if self.connection:
            self.connection.close()
            logger.info("Database connection closed")

def validate_input(data: str) -> bool:
    """Validate input data."""
    if not isinstance(data, str):
        return False
    if len(data) > 1000:  # Reasonable limit
        return False
    return True

def process_user_data(user_id: int, user_data: str) -> Optional[Dict]:
    """Process user data with proper validation."""
    if not validate_input(user_data):
        logger.warning(f"Invalid input data for user {user_id}")
        return None
    
    # Process the data
    processed_data = {
        'user_id': user_id,
        'data': user_data.upper(),
        'length': len(user_data),
        'processed_at': '2025-01-01'  # Would use datetime.now() in real code
    }
    
    return processed_data

def main():
    """Main function demonstrating clean code practices."""
    # Configuration from environment
    db_path = os.getenv('DATABASE_PATH', 'app.db')
    
    # Initialize database manager
    db_manager = DatabaseManager(db_path)
    
    if not db_manager.connect():
        logger.error("Failed to connect to database")
        return
    
    try:
        # Example: Get user data safely
        user_data = process_user_data(1, "test data")
        if user_data:
            logger.info(f"Processed user data: {user_data}")
        
        # Example: Execute safe query
        results = db_manager.execute_query(
            "SELECT * FROM users WHERE id = ?", 
            (1,)  # Parameterized query
        )
        logger.info(f"Query results: {len(results)} rows")
        
    except Exception as e:
        logger.error(f"Error in main: {e}")
    finally:
        db_manager.close()

if __name__ == "__main__":
    main()
