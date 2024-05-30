#!/usr/bin/env python3
"""
Encrypting passwords.
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """
    A function that expects one string argument name
    password and return a salted, hashed password, which is a byte string.
    """
    b = password.encode()
    hashed = hashpw(b, bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    A function that expect 2 arguments and returns a boolean.
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
