#!/usr/bin/env python3
"""
Test file with various code defects to test the CodeReviewer.AI bot
This file intentionally contains security vulnerabilities, code quality issues, 
performance problems, and best practice violations.
"""

import os
import requests
import sqlite3
import pickle
import subprocess

# Security Issues
def insecure_sql_query(user_id):
    """SQL injection vulnerability"""
    query = f"SELECT * FROM users WHERE id = {user_id}"
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(query)  # Vulnerable to SQL injection
    return cursor.fetchall()

def hardcoded_secrets():
    """Hardcoded secrets"""
    api_key = "sk-1234567890abcdef"
    password = "admin123"
    secret_token = "super_secret_token_here"
    return api_key, password, secret_token

def unsafe_deserialization(data):
    """Unsafe deserialization"""
    return pickle.loads(data)  # Dangerous!

def command_injection(user_input):
    """Command injection vulnerability"""
    command = f"ls {user_input}"
    return subprocess.call(command, shell=True)  # Shell injection risk

# Code Quality Issues
def very_long_function_with_many_responsibilities():
    """This function is too long and does too many things"""
    # Magic number
    max_retries = 3
    timeout = 5000
    
    # TODO: Refactor this function
    # FIXME: Add proper error handling
    # HACK: Temporary solution
    
    print("Starting process...")
    print("Processing data...")
    print("Almost done...")
    
    # Duplicate code
    for i in range(1000):
        if i % 2 == 0:
            print(f"Even number: {i}")
        else:
            print(f"Odd number: {i}")
    
    # More duplicate code
    for i in range(1000):
        if i % 2 == 0:
            print(f"Even number: {i}")
        else:
            print(f"Odd number: {i}")
    
    # Empty exception handling
    try:
        risky_operation()
    except:
        pass  # Silent failure
    
    return "Done"

def risky_operation():
    """Function that might fail"""
    raise Exception("Something went wrong!")

# Performance Issues
def inefficient_database_queries():
    """N+1 query problem"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Get all users
    cursor.execute("SELECT id FROM users")
    user_ids = cursor.fetchall()
    
    # N+1 problem: querying for each user individually
    users = []
    for user_id in user_ids:
        cursor.execute(f"SELECT * FROM users WHERE id = {user_id[0]}")
        user = cursor.fetchone()
        users.append(user)
    
    return users

def inefficient_list_operations():
    """Inefficient list operations"""
    # Inefficient: using range(len())
    my_list = [1, 2, 3, 4, 5]
    for i in range(len(my_list)):
        print(my_list[i])
    
    # Inefficient: appending in loop
    result = []
    for i in range(10000):
        result.append(i * 2)
    
    return result

# Best Practice Violations
def missing_error_handling():
    """Missing proper error handling"""
    # No validation or error handling
    file = open("nonexistent.txt", "r")
    content = file.read()
    file.close()
    return content

def hardcoded_values():
    """Hardcoded configuration values"""
    # Hardcoded URLs and values
    api_url = "http://localhost:3000/api"
    database_url = "127.0.0.1:5432"
    debug_mode = True
    
    return api_url, database_url, debug_mode

def missing_input_validation(data):
    """Missing input validation"""
    # No validation of input data
    return data.upper()

# Global variables (memory leak potential)
global_counter = 0
global_data = []

def use_global_variables():
    """Using global variables"""
    global global_counter, global_data
    global_counter += 1
    global_data.append("some data")
    return global_counter

if __name__ == "__main__":
    # Test all the problematic functions
    print("Testing various code defects...")
    
    # This will cause issues
    insecure_sql_query("1 OR 1=1")
    hardcoded_secrets()
    command_injection("; rm -rf /")
    very_long_function_with_many_responsibilities()
    inefficient_database_queries()
    missing_error_handling()
    hardcoded_values()
    missing_input_validation(None)
    use_global_variables()
    
    print("Test completed!")
