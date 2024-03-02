import hashlib
import sqlite3
from contextlib import contextmanager
from typing import List, NamedTuple, Tuple
from datetime import datetime

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
DB_NAME = "./db.sqlite"


@contextmanager
def connect(db_name):
    # sticking all the boilerplate here
    conn = sqlite3.connect(db_name)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.cursor()
        yield cur
    except Exception as e:
        conn.rollback()
        raise e
    else:
        conn.commit()
    finally:
        conn.close()

def insert_user(username: str, authn_method: str, password: str | None = None):
    if password is not None:
        password_bytes = password.encode("utf-8")
        password_sha1 = hashlib.sha1(password_bytes).hexdigest()
        password_sha1_salt = hashlib.sha1(SALT + password_bytes).hexdigest()
    else:
        password_sha1 = None
        password_sha1_salt = None

    with connect(DB_NAME) as cur:
        cur.execute(
            """
        INSERT INTO users
        (username, authn_method, password, password_sha1, password_sha1_salt)
        VALUES (?, ?, ?, ?, ?)
        """,
            [username, authn_method, password, password_sha1, password_sha1_salt],
        )


def select_user(username: str) -> Tuple[int, str, str] | None:
    with connect(DB_NAME) as cur:
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
    return None


def check_user_password(username: str, password: str) -> Tuple[bool, int | None]:
    password_bytes = password.encode("utf-8")
    password_sha1_salt = hashlib.sha1(SALT + password_bytes).hexdigest()
    with connect(DB_NAME) as cur:
        res = cur.execute(
            "SELECT id, password_sha1_salt FROM users WHERE username = ?", [username]
        ).fetchone()
        if res is not None and res[1] == password_sha1_salt:
            return (res[0], res[1])
    return (False, None)


def insert_authenticator(username: str, id: str, pk: str) -> None:
    with connect(DB_NAME) as cur:
        user_id = cur.execute(
            "SELECT id FROM users WHERE username = ?", [username]
        ).fetchone()[0]
        cur.execute(
            """
            INSERT INTO webauthn
            (user_id, created_on, authn_id, authn_pk)
            VALUES (?, ?, ?, ?)
            """,
            [user_id, datetime.now().strftime(r"%Y/%m/%d %H:%M"), id, pk],
        )


class Authenticator(NamedTuple):
    id: bytes
    pk: bytes
    created_on: str


def select_authenticators(username: str) -> List[Authenticator]:
    """Return list of tuples of form [id, pk]"""
    with connect(DB_NAME) as cur:
        # get user_id or return empty list
        res = cur.execute(
            "SELECT id FROM users WHERE username = ?", [username]
        ).fetchone()
        if res is None:
            return []
        user_id = res["id"]
        # select authenticators matching user_id
        res = cur.execute(
            """
            SELECT
            authn_id,
            authn_pk,
            created_on
            FROM webauthn
            WHERE user_id = ?
            """,
            [user_id],
        )

        return [
            Authenticator(
                id=row["authn_id"], pk=row["authn_pk"], created_on=row["created_on"]
            )
            for row in res.fetchall()
        ]


def select_authenticator_pk(id: bytes) -> bytes | None:
    with connect(DB_NAME) as cur:
        # get user_id or return empty list
        res = cur.execute(
            "SELECT authn_pk FROM webauthn WHERE authn_id = ?", [id]
        ).fetchone()
        if res is not None:
            return res[0]
        return None


def delete_authenticator(id: bytes) -> None:
    with connect(DB_NAME) as cur:
        cur.execute("DELETE FROM webauthn WHERE authn_id = ?", [id])
