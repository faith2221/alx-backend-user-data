#!/usr/bin/env python3
"""
Encrypting passwords.
"""

import bcrypt


def hash_password(pasword: str) -> bytes:
    """
    A function that expects one string argument name
    password and return a salted, hashed password, which is a byte string.
    """
    if password:
        return bcrypt.hashpw(str.encode(password), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    A function that expect 2 arguments and returns a boolean.
    """
    if hashed_password and password:
        return bcrypt.checkpw(str.encode(password), hashed_password)
