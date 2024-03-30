#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

mkdir -p "$SCRIPT_DIR/client"
cd "$SCRIPT_DIR/client"

if [ ! -f leaf_key.pem ]; then
    openssl req -x509 -newkey rsa:4096 \
        -keyout ca_key.pem -out ca_cert.pem -noenc \
        -days 3650 -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"

    openssl req -x509 -newkey rsa:4096 \
        -CAkey ca_key.pem -CA ca_cert.pem \
        -keyout leaf_key.pem -out leaf_cert.pem -noenc \
        -days 3650 -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"
fi

echo "Fetching token:"
curl --insecure -X POST https://localhost:8080/token \
    --key leaf_key.pem --cert leaf_cert.pem \
    -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token_type=urn:ietf:params:oauth:token-type:tls-client-auth&audience=test"

echo ""
echo "Fetching openid configuration and jwks:"
curl --insecure -X GET https://localhost:8080/bedfac3e22a963ef849a5755b9b845f718ca2bc260a0f1b4bb0fdfd78625531f/.well-known/openid-configuration \
    --key leaf_key.pem --cert leaf_cert.pem

echo ""
curl --insecure -X GET https://localhost:8080/bedfac3e22a963ef849a5755b9b845f718ca2bc260a0f1b4bb0fdfd78625531f/.well-known/jwks \
    --key leaf_key.pem --cert leaf_cert.pem
