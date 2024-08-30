#!/usr/bin/env python3
"""
Main file for handling sensitive data and interacting with the database.
"""

import logging
from encrypt_password import hash_password, is_valid
from filtered_logger import RedactingFormatter, filter_datum, get_db, get_logger, PII_FIELDS

def main():
    # Redact sensitive data in messages
    fields = ["password", "date_of_birth"]
    messages = [
        "name=egg;email=eggmin@eggsample.com;password=eggcellent;date_of_birth=12/12/1986;",
        "name=bob;email=bob@dylan.com;password=bobbycool;date_of_birth=03/04/1993;"
    ]
    
    print("Redacted Messages:")
    for message in messages:
        print(filter_datum(fields, 'xxx', message, ';'))

    # Format and log a message with sensitive data
    message = "name=Bob;email=bob@dylan.com;ssn=000-123-0000;password=bobby2019;"
    log_record = logging.LogRecord("my_logger", logging.INFO, None, None, message, None, None)
    formatter = RedactingFormatter(fields=("email", "ssn", "password"))
    print("\nFormatted Log Record:")
    print(formatter.format(log_record))

    # Display logger annotations and PII fields count
    print("\nLogger Annotations:")
    print(get_logger.__annotations__.get('return'))
    print("PII_FIELDS count: {}".format(len(PII_FIELDS)))

    # Interact with the database
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users;")
        
        print("\nUser Data from Database:")
        for row in cursor:
            print(row[0])
            
        cursor.close()
        db.close()
    except Exception as e:
        print(f"Database error: {e}")

    # Password encryption and validation
    password = "medhat2030"
    encrypted_password = hash_password(password)
    print("\nPassword Encryption:")
    print(f"Encrypted Password: {encrypted_password}")
    print(f"Is Valid: {is_valid(encrypted_password, password)}")

if __name__ == "__main__":
    main()
