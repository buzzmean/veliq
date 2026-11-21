#!/usr/bin/env python3
"""Generate private PostgreSQL provisioning SQL; password never enters argv."""
import pathlib
import sys


def generate(password: str) -> str:
    if not password or '\x00' in password:
        raise ValueError('Database password must be nonempty and contain no NUL')
    # Explicit standard strings make backslashes literal, regardless of server defaults.
    literal = "'" + password.replace("'", "''") + "'"
    return ("SET standard_conforming_strings = on;\n"
            f"CREATE ROLE neexitlag LOGIN PASSWORD {literal};\n"
            "CREATE DATABASE neexitlag OWNER neexitlag;\n")


if __name__ == '__main__':
    # Preserve password bytes, including whitespace/newlines; do not silently alter credentials.
    password = pathlib.Path(sys.argv[1]).read_bytes().decode('utf-8')
    sys.stdout.write(generate(password))
