import sqlite3
import hashlib
from typing import List, Tuple

# sqlite3 stuff goes here

# CREATE TABLE users (
#     id INTEGER PRIMARY KEY,
#     username TEXT,
#     authn_method TEXT,
#     password TEXT,
#     password_sha1 TEXT,
#     password_sha1_salt TEXT
# );

# CREATE TABLE webauthn (
#     user_id TEXT,
#     label TEXT,
#     authn_user_id BLOB,
#     authn_id BLOB,
#     authn_pk BLOB
# );

SALT = b"salt"


def insert_user(username: str, authn_method: str, password: str | None = None):
    if password is not None:
        password_bytes = password.encode("utf-8")
        password_sha1 = hashlib.sha1(password_bytes).hexdigest()
        password_sha1_salt = hashlib.sha1(SALT + password_bytes).hexdigest()
    else:
        password_sha1 = None
        password_sha1_salt = None

    print(password)

    con = sqlite3.connect("./db.sqlite")
    cur = con.cursor()
    cur.execute(
        """
        INSERT INTO users
        (username, authn_method, password, password_sha1, password_sha1_salt)
        VALUES (?, ?, ?, ?, ?)
        """,
        [username, authn_method, password, password_sha1, password_sha1_salt],
    )
    con.commit()
    con.close()


def select_user(username: str) -> Tuple[int, str, str] | None:
    try:
        con = sqlite3.connect("./db.sqlite")
        cur = con.cursor()
        res = cur.execute(
            """
            SELECT id, username, password
            FROM users
            WHERE username = ?""",
            [username],
        )
        user = res.fetchone()
        if user is not None:
            return user
    finally:
        con.close()

    return None


def check_user_password(username: str, password: str) -> Tuple[bool, int|None]:
    password_bytes = password.encode("utf-8")
    password_sha1_salt = hashlib.sha1(SALT + password_bytes).hexdigest()
    try:
        con = sqlite3.connect("./db.sqlite")
        cur = con.cursor()
        res = cur.execute(
            "SELECT id, password_sha1_salt FROM users WHERE username = ?", [username]
        ).fetchone()
        if res is not None and res[1] == password_sha1_salt:
            return (res[0], res[1])
    finally:
        con.close()

    return (False, None)


def insert_authenticator(username: str, id: str, pk: str):
    try:
        con = sqlite3.connect("./db.sqlite")
        cur = con.cursor()
        user_id = cur.execute(
            "SELECT id FROM users WHERE username = ?", [username]
        ).fetchone()[0]
        cur.execute(
            """INSERT INTO webauthn
            (user_id, authn_id, authn_pk)
            VALUES (?, ?, ?)
            """,
            [user_id, id, pk],
        )
        con.commit()
    finally:
        con.close()


def select_authenticators(username: str) -> List[Tuple[bytes, bytes]]:
    """Return list of tuples of form [id, pk]"""
    try:
        con = sqlite3.connect("./db.sqlite")
        cur = con.cursor()
        # get user_id or return empty list
        res = cur.execute(
            "SELECT id FROM users WHERE username = ?", [username]
        ).fetchone()
        if res is None:
            return []
        user_id = res[0]
        res = cur.execute(
            """
            SELECT authn_id, authn_pk
            FROM webauthn
            WHERE user_id = ?
            """,
            [user_id],
        )
        return [(row[0], row[1]) for row in res.fetchall()]

    finally:
        con.close()


def select_authenticator_pk(id: bytes) -> bytes | None:
    try:
        con = sqlite3.connect("./db.sqlite")
        cur = con.cursor()
        # get user_id or return empty list
        res = cur.execute(
            "SELECT authn_pk FROM webauthn WHERE authn_id = ?", [id]
        ).fetchone()
        if res is not None:
            return res[0]
    finally:
        con.close()

    return None


def delete_authenticator():
    pass
