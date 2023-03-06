#!/usr/bin/env python3
""" validate provided password matches using bcrypt """
import bcrypt


def hash_password(password: str) -> bytes:
    """
    byte string
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    validate provided password
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
