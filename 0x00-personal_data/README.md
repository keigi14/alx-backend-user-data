# 0x00. Personal Data

## Overview
This project focuses on the back-end and authentication aspects related to personal data. We will implement functions and classes to handle personal data securely, such as obfuscating Personally Identifiable Information (PII) fields, hashing passwords, and authenticating with a secure database. The goal is to ensure the protection of sensitive information.

## Learning Objectives
At the end of this project, you are expected to be able to explain to anyone, without the help of Google:
- Examples of Personally Identifiable Information (PII)
- How to implement a log filter that will obfuscate PII fields
- How to encrypt a password and check the validity of an input password
- How to authenticate to a database using environment variables

## Requirements
- All your files will be interpreted/compiled on Ubuntu 18.04 LTS using Python 3 (version 3.7)
- All your files should end with a new line
- The first line of all your files should be exactly `#!/usr/bin/env python3`
- A `README.md` file, at the root of the folder of the project, is mandatory
- Your code should use the `pycodestyle` style (version 2.5)
- All your files must be executable
- The length of your files will be tested using `wc`
- All your modules should have a documentation (`python3 -c 'print(__import__("my_module").__doc__)'`)
- All your classes should have a documentation (`python3 -c 'print(__import__("my_module").MyClass.__doc__)'`)
- All your functions (inside and outside a class) should have a documentation (`python3 -c 'print(__import__("my_module").my_function.__doc__)'` and `python3 -c 'print(__import__("my_module").MyClass.my_function.__doc__)'`)
- A documentation is not a simple word, it’s a real sentence explaining the purpose of the module, class, or method (the length of it will be verified)
- All your functions should be type-annotated

## Tasks
### 0. Regex-ing
Implement a function called `filter_datum` that returns the log message obfuscated according to specified fields using regular expressions.

### 1. Log formatter
Update the `RedactingFormatter` class to accept a list of strings `fields` constructor argument. Implement the `format` method to filter values in incoming log records using `filter_datum`.

### 2. Create logger
Implement a `get_logger` function that returns a `logging.Logger` object. The logger should be named "user_data" and only log up to `logging.INFO` level. It should not propagate messages to other loggers. It should have a `StreamHandler` with `RedactingFormatter` as the formatter.

### 3. Connect to a secure database
Implement a `get_db` function that returns a connector to a MySQL database using credentials obtained from environment variables.

### 4. Read and filter data
Implement a `main` function that retrieves all rows in the users' table from the secure database and displays each row under a filtered format.

### 5. Encrypting passwords
Implement a `hash_password` function that takes a password and returns a salted, hashed password using bcrypt.

### 6. Check valid password
Implement an `is_valid` function that takes a hashed password and a password, and returns a boolean indicating whether the provided password matches the hashed password.

## Resources
To successfully complete this project, you may need to read or watch about the following topics:
- Personally Identifiable Information (PII) and personal data
- Regular expressions in Python
- Logging in Python
- Bcrypt for password hashing
- Working with MySQL databases
- Environment variables in Python

## Repo
This project is part of the ALX Backend curriculum. You can find the code files in the [alx-backend-user-data/0x00-personal_data](https://github.com/alx-backend-user-data/0x00-personal_data) directory. The main scripts to run are:
- `filtered_logger.py` for tasks 0 to 4.
- `encrypt_password.py` for tasks 5 and 6.
