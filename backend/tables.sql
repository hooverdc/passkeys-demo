DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    authn_method TEXT,
    password TEXT,
    password_sha1 TEXT,
    password_sha1_salt TEXT
);

DROP TABLE IF EXISTS webauthn;
CREATE TABLE webauthn (
    user_id INTEGER,
    label TEXT,
    created_on TEXT,
    authn_id BLOB,
    authn_pk BLOB
);