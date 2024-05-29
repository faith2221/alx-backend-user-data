#!/usr/bin/env python3
"""
A function called filter_datum that returns the log.
"""
from typing import List
import re
import logging
import csv
import os
import mysql.connector

PII_FIELDS = ("name", "email", "phone", "ssn", "password")


class RedactingFormatter(logging.Formatter):
    """
    Redacting Formatter class.
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Initializing self.
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Filters values in incoming log records using filter_datum.
        """
        return filter_datum(self.fields, self.REDACTION,
                            super(RedactingFormatter, self).format(record),
                            self.SEPARATOR)


def filter_datum(fields: List[str], redaction: str, message: str,
                 separator: str) -> str:
    """
    Returns the log message obfuscated
    fields: a list of strings representing all fields to obfuscate
    redaction: a string representing by what the field will be obfuscated
    message: a string representing the log line
    separator: a string representing by which char is separating all fields
    """
    return re.sub(r"(\w+)=([a-zA-Z0-9@\.\-\(\)\ \:\^\<\>\~\$\%\@\?\!\/]*)",
                  lambda match: match.group(1) + "=" + redaction
                  if match.group(1) in fields else match.group(0), message)


def get_logger() -> logging.Logger:
    """
    Returns a logging.Logger object.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.addHandler(stream_handler)

    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Connect to secure database.
    """
    return mysql.connector.connect(
        host=os.getenv("PERSONAL_DATA_DB_HOST", "root"),
        database=os.getenv("PERSONAL_DATA_DB_NAME"),
        user=os.getenv("PERSONAL_DATA_DB_USERNAME", "localhost"),
        password=os.getenv("PERSONAL_DATA_DB_PASSWORD", ""),
    )


def main():
    """
    The main function.
    """
    conn = get_db()
    users = conn.cursor()
    users.execute("SELECT CONTACT('name=', name, ';ssn=' ssn, ';ip=', ip, \
        ';user_agent', user_agent, ';')AS message FROM users;")
    formatter = RedactingFormatter(fields=PII_FIELDS)
    logger = get_logger()

    for user in users:
        logger.log(logging.INFO, user[0])


if __name__ == "__main__":
    main()
