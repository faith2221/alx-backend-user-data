#!/usr/bin/env python3
"""
Definition of hash_password function.
"""
import bcrypt
from db import DB
from user import User
from uuid import uuid4
from sqlalchemy.orm.exc import NoResultFound

from typing import Union


def _hash_password(password: str) -> str:
    """
    hashes a password string and returns it in bytes form.
    """
    passwd = password.encode('utf-8')
    return bcrypt.hashpw(passwd, bcrypt.gensalt())


def _generate_uuid() -> str:
    """
    generate a uuid and return string representation.
    """
    id = uuid4()
    return str(id)


class Auth:
    """
    auth class to interact with the authentication database.
    """

    def __init__(self):
        """
        main
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> Union[None, User]:
        """
        register a new user and return a user object.
        """
        try:
            # find the user with the given email
            self._db.find_user_by(email=email)
        except NoResultFound:
            # add user to the database
            return self._db.add_user(email, _hash_password(password))

        else:
            # if user already exists, throw error
            raise ValueError('User {} already exists'.format(email))

    def valid_login(self, email: str, password: str) -> bool:
        """
        validate a user's login credentials and return True
        if they are correct or False if they are not.
        """
        try:
            # find the user with the given email
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False

        passwd = password.encode('utf-8')
        return bcrypt.checkpw(passwd, user.hashed_password)

    def create_session(self, email: str) -> str:
        """
        create a session_id for an existing user and update the user's
        session_id attribute.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        else:
            user.session_id = _generate_uuid()
            return user.session_id

    def get_user_from_session_id(self, session_id: str) -> User:
        """
        takes a session_id and returns the corresponding user,
        if one exists, else returns None.
        """
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        else:
            return user

    def destroy_session(self, user_id: str) -> None:
        """
        take user_id and destroy that user's session and update their
        session_id attribute to None
        """
        try:
            user = self._db.find_user_by(id=user_id)
        except NoResultFound:
            return None
        else:
            user.session_id = None
            return None

    def get_reset_password_token(self, email: str) -> str:
        """
        generates a reset_token uuid for user identified by the given email.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError
        else:
            user.reset_token = _generate_uuid()
            return user.reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """
        update's user's new password.
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError
        else:
            user.hashed_password = _hash_password(password)
            user.reset_token = None
            return None
