"""
Pytest configuration and shared fixtures.
"""
import sys
import os

# Ensure the project root is on the Python path so all modules resolve.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
