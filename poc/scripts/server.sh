#!/bin/bash

ROOT=$(realpath .)

(
    cd "$ROOT/www"
    openssl s_server \
        -CAfile "$ROOT/certs/ca_cert.pem" \
        -cert "$ROOT/certs/server_cert.pem" \
        -key "$ROOT/certs/server_key.pem" \
        -HTTP -port 5008 -tls1
)
