#!/bin/bash

export WEBAUTHN_RP_ID="passkeys-demo.hooverd.com"
export WEBAUTHN_RP_NAME="Passkeys Demo"
export WEBAUTHN_ORIGIN="https://passkeys-demo.hooverd.com"

gunicorn -w "4" -b "127.0.0.1:8080" "src.app:app" --daemon
