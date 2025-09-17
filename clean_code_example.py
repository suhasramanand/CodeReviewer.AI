"""
Clean Code Example - Demonstrates best practices for Python development.

This module contains examples of clean, secure, and well-structured Python code
that should pass all code review checks.
"""

import logging
import hashlib
import secrets
from typing import List, Dict, Optional
from dataclasses import dataclass
from pathlib import Path


# Constants
MAX_RETRY_ATTEMPTS = 3
DEFAULT_TIMEOUT = 30
HASH_ALGORITHM = "sha256"


@dataclass
class User:
    """User data class with proper validation."""
    username: str
    email: str
    is_active: bool = True
    
    def __post_init__(self):
        """Validate user data after initialization."""
        if not self.username or len(self.username) < 3:
            raise ValueError("Username must be at least 3 characters long")
        if "@" not in self.email:
            raise ValueError("Invalid email format")


class SecurePasswordManager:
    """Secure password management with proper hashing."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def hash_password(self, password: str) -> str:
        """Hash password using secure salt and algorithm."""
        if not password:
            raise ValueError("Password cannot be empty")
        
        # Generate secure random salt
        salt = secrets.token_hex(32)
        
        # Hash password with salt
        password_hash = hashlib.pbkdf2_hmac(
            HASH_ALGORITHM,
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # iterations
        )
        
        return f"{salt}:{password_hash.hex()}"
    
    def verify_password(self, password: str, stored_hash: str) -> bool:
        """Verify password against stored hash."""
        try:
            salt, hash_hex = stored_hash.split(':')
            password_hash = hashlib.pbkdf2_hmac(
                HASH_ALGORITHM,
                password.encode('utf-8'),
                salt.encode('utf-8'),
                100000
            )
            return secrets.compare_digest(hash_hex, password_hash.hex())
        except (ValueError, TypeError):
            self.logger.warning("Invalid hash format during verification")
            return False


class DatabaseConnection:
    """Secure database connection with proper error handling."""
    
    def __init__(self, connection_string: str):
        self.connection_string = connection_string
        self.logger = logging.getLogger(__name__)
    
    def execute_query(self, query: str, parameters: Optional[Dict] = None) -> List[Dict]:
        """Execute parameterized query safely."""
        if not query.strip():
            raise ValueError("Query cannot be empty")
        
        # Validate query doesn't contain dangerous patterns
        dangerous_patterns = ['DROP', 'DELETE', 'UPDATE', 'INSERT', 'EXEC']
        query_upper = query.upper()
        
        for pattern in dangerous_patterns:
            if pattern in query_upper:
                raise ValueError(f"Dangerous SQL pattern detected: {pattern}")
        
        try:
            # Simulate safe database execution
            self.logger.info(f"Executing query: {query[:50]}...")
            return []  # Mock result
        except Exception as e:
            self.logger.error(f"Database error: {str(e)}")
            raise
    
    def close(self):
        """Close database connection safely."""
        self.logger.info("Closing database connection")


class FileManager:
    """Secure file operations with proper validation."""
    
    def __init__(self, base_path: str):
        self.base_path = Path(base_path).resolve()
        self.logger = logging.getLogger(__name__)
    
    def read_file(self, filename: str) -> str:
        """Read file with path traversal protection."""
        # Validate filename
        if not filename or '..' in filename or filename.startswith('/'):
            raise ValueError("Invalid filename")
        
        file_path = self.base_path / filename
        
        # Ensure file is within base path
        try:
            file_path.resolve().relative_to(self.base_path)
        except ValueError:
            raise ValueError("Path traversal attempt detected")
        
        try:
            return file_path.read_text(encoding='utf-8')
        except FileNotFoundError:
            self.logger.warning(f"File not found: {filename}")
            raise
        except Exception as e:
            self.logger.error(f"Error reading file {filename}: {str(e)}")
            raise
    
    def write_file(self, filename: str, content: str) -> None:
        """Write file with proper validation."""
        if not filename or '..' in filename or filename.startswith('/'):
            raise ValueError("Invalid filename")
        
        file_path = self.base_path / filename
        
        try:
            file_path.resolve().relative_to(self.base_path)
        except ValueError:
            raise ValueError("Path traversal attempt detected")
        
        try:
            file_path.write_text(content, encoding='utf-8')
            self.logger.info(f"Successfully wrote file: {filename}")
        except Exception as e:
            self.logger.error(f"Error writing file {filename}: {str(e)}")
            raise


def calculate_fibonacci(n: int) -> int:
    """Calculate nth Fibonacci number efficiently."""
    if n < 0:
        raise ValueError("Fibonacci sequence is not defined for negative numbers")
    
    if n <= 1:
        return n
    
    a, b = 0, 1
    for _ in range(2, n + 1):
        a, b = b, a + b
    
    return b


def process_user_data(users: List[User]) -> Dict[str, int]:
    """Process user data with proper error handling."""
    if not users:
        return {"total": 0, "active": 0}
    
    try:
        total_users = len(users)
        active_users = sum(1 for user in users if user.is_active)
        
        return {
            "total": total_users,
            "active": active_users,
            "inactive": total_users - active_users
        }
    except Exception as e:
        logging.getLogger(__name__).error(f"Error processing user data: {str(e)}")
        raise


def main():
    """Main function demonstrating clean code usage."""
    logging.basicConfig(level=logging.INFO)
    
    try:
        # Create secure password manager
        password_manager = SecurePasswordManager()
        
        # Hash a password
        password_hash = password_manager.hash_password("secure_password_123")
        print(f"Password hashed successfully")
        
        # Verify password
        is_valid = password_manager.verify_password("secure_password_123", password_hash)
        print(f"Password verification: {'Success' if is_valid else 'Failed'}")
        
        # Create user
        user = User("john_doe", "john@example.com")
        print(f"User created: {user.username}")
        
        # Calculate Fibonacci
        fib_result = calculate_fibonacci(10)
        print(f"Fibonacci(10) = {fib_result}")
        
        # Process user data
        users = [user, User("jane_doe", "jane@example.com", False)]
        stats = process_user_data(users)
        print(f"User statistics: {stats}")
        
    except Exception as e:
        logging.error(f"Application error: {str(e)}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
