from typing import Literal
from flask import Flask, send_from_directory, session, request
from dataclasses import dataclass
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    COSEAlgorithmIdentifier,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
)
from secrets import token_bytes
import sqlite3

from .db import (
    insert_user,
    insert_authenticator,
    select_authenticators,
    check_user_password,
    select_authenticator_pk,
)


def json_response(body: str, status_code: int = 200):
    return body, status_code, {"Content-Type": "application/json"}


RP_ID = "localhost"
RP_NAME = "localhost"
# picky
ORIGIN = "http://localhost:5000"
TIMEOUT = 60000

app = Flask(__name__, static_folder="../../frontend/dist", static_url_path="/")

app.secret_key = "secret"


# serve SPA?
@app.route("/")
def index():
    return send_from_directory("../../frontend/dist", path="index.html")


# /user
# get user
@app.route("/auth/user")
def user():
    # TODO get user from DB
    raise NotImplementedError()


# /login
@app.route("/password/register", methods=["POST"])
def register():
    """Register with password"""
    # wow this is so much simpler after all that
    credential = request.json
    # don't do this
    print(credential)
    user_name = credential["user_name"]
    password = credential["password"]
    try:
        insert_user(user_name, "password", password=password)
    except sqlite3.IntegrityError:
        return {"success": False, "error": "Username already registered."}, 500

    return {"success": True}


# /login
@app.route("/password/login", methods=["POST"])
def login():
    """Login with password"""
    credential = request.json
    # don't do this
    print(credential)
    user_name = credential["user_name"]
    password = credential["password"]
    try:
        is_valid, user_id = check_user_password(user_name, password)
        if is_valid:
            session["user_id"] = user_id
            return {"success": True}, 200
    except sqlite3.IntegrityError:
        return {"success": False, "error": "Internal server error"}, 500

    return {"success": False, "error": "Invalid password"}, 401


# /logout
@app.route("/auth/logout")
def logout():
    # clear our session cookies
    session.clear()
    return {"success": True}, 200


# /webauthn/register/options
@app.route("/webauthn/register/options")
def webauthn_register_options():
    # ?username=zzz
    user_name = request.args.get("user_name")
    if user_name is None:
        return {"error": "Bad request"}, 400
    session["user_name"] = user_name

    challenge = token_bytes(32)
    session["challenge"] = challenge

    # different from our backend user ID blah
    user_id = token_bytes(32)
    session["authn_user_id"] = user_id

    authenticators = select_authenticators(user_name)
    # this lets us check for existing credentials if we try and re-register
    exclude_credentials = [
        PublicKeyCredentialDescriptor(authenticator[0])
        for authenticator in authenticators
    ]

    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_name=user_name,
        user_id=user_id,
        challenge=challenge,
        timeout=TIMEOUT,
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria,
        # TODO get existing PK credentials
        exclude_credentials=exclude_credentials,
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ],
    )
    options_json = options_to_json(options)
    return json_response(options_json)


# /webauthn/register
@app.route("/webauthn/register", methods=["POST"])
def webauthn_register():
    credential = request.json
    try:
        verified_response = verify_registration_response(
            credential=credential,
            expected_challenge=session["challenge"],
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            require_user_verification=False,
            supported_pub_key_algs=[
                COSEAlgorithmIdentifier.ECDSA_SHA_256,
                COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
            ],
        )
        print(verified_response)
    except Exception as ex:
        print(ex)
        # lots of things can go wrong here
        return {"success": False, "error": "Passkey registration failed."}, 500

    try:
        insert_user(session["user_name"], "webauthn")
    except sqlite3.IntegrityError:
        return {"success": False, "error": "Username already registered."}, 500

    # save authenticator id and public key to database
    try:
        insert_authenticator(
            session["user_name"],
            verified_response.credential_id,
            verified_response.credential_public_key,
        )
    except sqlite3.IntegrityError:
        return {
            "success": False,
            "error": "You managed to register a username but not an authenticator. Whoops!",
        }, 500

    del session["challenge"]

    return {"success": True}, 200


# /webauthn/authenticate/options
@app.route("/webauthn/authenticate/options")
def webauthn_authenticate_options():
    # ?username=zzz
    user_name = request.args.get("user_name")
    if user_name is None:
        return {"error": "Bad request"}, 400
    session["user_name"] = user_name

    challenge = token_bytes(32)
    session["challenge"] = challenge

    authenticators = select_authenticators(user_name)
    # provide list of credentials user can authenticate with
    allow_credentials = [
        PublicKeyCredentialDescriptor(authenticator[0])
        for authenticator in authenticators
    ]
    # you can make up fake authenticators if a user doesn't have any
    # to help prevent username enumeration

    options = generate_authentication_options(
        rp_id=RP_ID,
        challenge=challenge,
        timeout=TIMEOUT,
        allow_credentials=allow_credentials,
    )

    options_json = options_to_json(options)
    return json_response(options_json)


# /webauthn/authenticate
@app.route("/webauthn/authenticate", methods=["POST"])
def webauthn_authenticate():
    credential = request.json
    try:
        id_b64 = credential["id"]
        id_bytes = base64url_to_bytes(id_b64)
        public_key = select_authenticator_pk(id_bytes)
        if public_key is None:
            raise RuntimeError("No public key found for authenticator ID")
    except Exception as ex:
        print(ex)
        return {"success": False, "error": "Passkey authentication failed."}, 500

    try:
        verified_response = verify_authentication_response(
            credential=credential,
            expected_challenge=session["challenge"],
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=public_key,
            # always zero
            # it's more for yubikeys and stuff
            credential_current_sign_count=0,
        )
        print(verified_response)
    except Exception as ex:
        print(ex)
        # lots of things can go wrong here
        return {"success": False, "error": "Passkey authentication failed."}, 500

    return {"success": True}, 200
