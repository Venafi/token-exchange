#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

mkdir -p "$SCRIPT_DIR/client"
cd "$SCRIPT_DIR/client"

if [ ! -f ca_key.pem ]; then
    openssl req -x509 -newkey rsa:4096 \
        -keyout ca_key.pem -out ca_cert.pem -noenc \
        -days 3650 -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CA"
fi

if [ ! -f leaf1_key.pem ]; then
    openssl req -x509 -newkey rsa:4096 \
        -CAkey ca_key.pem -CA ca_cert.pem \
        -keyout leaf1_key.pem -out leaf1_cert.pem -noenc \
        -days 3650 -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=Identity1"

    cat leaf1_cert.pem ca_cert.pem > leaf1_cert_chain.pem
        
    openssl req -x509 -newkey rsa:4096 \
        -CAkey ca_key.pem -CA ca_cert.pem \
        -keyout leaf2_key.pem -out leaf2_cert.pem -noenc \
        -days 3650 -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=Identity2"

    cat leaf2_cert.pem ca_cert.pem > leaf2_cert_chain.pem
fi

if [ "${LOCAL:-0}" -eq 1 ]; then
    tokenurl="https://localhost:7000"
    url="http://localhost:8000"
else
    tokenurl="https://rnhzf-2a02-a03f-e9bc-1e00-be86-1073-3cda-202a.a.free.pinggy.link:39881"
    url="https://rnzlf-2a02-a03f-e9bc-1e00-be86-1073-3cda-202a.a.free.pinggy.link"
fi

echo "Fetching token:"
curl --insecure -X POST "$tokenurl/token" \
    --key leaf1_key.pem --cert leaf1_cert_chain.pem \
    -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token_type=urn:ietf:params:oauth:token-type:tls-client-auth&audience=test"

echo ""
curl --insecure -X POST "$tokenurl/token" \
    --key leaf2_key.pem --cert leaf2_cert_chain.pem \
    -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token_type=urn:ietf:params:oauth:token-type:tls-client-auth&audience=test"

echo ""
echo "Fetching openid configuration and jwks:"
curl -X GET "$url/6bb9f41650efddc312a65461fc2d704bf12fbbd7a3a67e01704753a3074cbf78/.well-known/openid-configuration"

echo ""
curl -X GET "$url/6bb9f41650efddc312a65461fc2d704bf12fbbd7a3a67e01704753a3074cbf78/.well-known/jwks"
