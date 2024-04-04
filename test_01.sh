#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

YELLOW='\033[1;33m'
NOCOLOR='\033[0m'

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
    tokenurl="https://token.tim-ramlot-gcp.jetstacker.net"
    url="https://discover.tim-ramlot-gcp.jetstacker.net"
fi

audience="test"

echo -e "$YELLOW> Fetching token from "$tokenurl" for audience "$audience" using leaf1$NOCOLOR"
token1=$(curl -s -X POST "$tokenurl/token" \
    --key leaf1_key.pem --cert leaf1_cert_chain.pem \
    -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token_type=urn:ietf:params:oauth:token-type:tls-client-auth&audience=$audience")

echo "$token1" | jq
echo ">> Decoded token:"
echo "$token1" | jq .access_token | jq -R 'split(".") | .[1] | @base64d | fromjson'
issuer1=$(echo "$token1" | jq .access_token | jq -R 'split(".") | .[1] | @base64d | fromjson | .iss' | tr -d '"')
jwt1=$(echo "$token1" | jq .access_token | tr -d '"')

echo ""

echo -e "$YELLOW> Fetching token from "$tokenurl" for audience "$audience" using leaf2$NOCOLOR"
token2=$(curl -s -X POST "$tokenurl/token" \
    --key leaf2_key.pem --cert leaf2_cert_chain.pem \
    -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token_type=urn:ietf:params:oauth:token-type:tls-client-auth&audience=$audience")

echo "$token2" | jq
echo ">> Decoded token:"
echo "$token2" | jq .access_token | jq -R 'split(".") | .[1] | @base64d | fromjson'
issuer2=$(echo "$token2" | jq .access_token | jq -R 'split(".") | .[1] | @base64d | fromjson | .iss' | tr -d '"')
jwt2=$(echo "$token2" | jq .access_token | tr -d '"')

if [ "$issuer1" != "$issuer2" ]; then
    echo "Issuers are different! (should never happen)"
    exit 1
fi

echo ""
echo -e "$YELLOW> Fetching openid configuration \"$issuer1/.well-known/openid-configuration\"$NOCOLOR"
curl -s -X GET "$issuer1/.well-known/openid-configuration" | jq

echo -e "$YELLOW> Fetching jwks \"$issuer1/.well-known/jwks\"$NOCOLOR"
curl -s -X GET "$issuer1/.well-known/jwks" | jq

# Example using the token to authenticate against the Venafi control plane
curl -s -X POST https://api.venafi.cloud/v1/oauth2/v2.0/c0f2c691-ab9b-11ed-bfed-b3b2b59a7f20/token \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -H 'Accept: application/json' \
    -d "grant_type=client_credentials&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=$jwt2" | jq '.access_token = "<REDACTED>"'

# Other possible use case is to authenticate against Public cloud provider APIs like GCP, AWS, Azure, etc.
