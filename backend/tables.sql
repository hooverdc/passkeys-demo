DROP TABLE users;
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    authn_method TEXT,
    password TEXT,
    password_sha1 TEXT,
    password_sha1_salt TEXT
);

DROP TABLE webauthn;
CREATE TABLE webauthn (
    user_id INTEGER,
    label TEXT,
    authn_user_id BLOB,
    authn_id BLOB,
    authn_pk BLOB
);