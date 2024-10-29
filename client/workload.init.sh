#!/bin/bash

CERT_FILES=( $(IFS=" " echo "${CERT_FILES:-/var/run/secrets/spiffe.io/tls.crt /var/run/secrets/spiffe.io/ca.crt}") )
KEY_FILE=${KEY_FILE:=/var/run/secrets/spiffe.io/tls.key}

# Use online token exchange so the URL is publicly available and trusted.
# TOKEN_URL=${TOKEN_URL:=https://token-exchange-token.token-exchange.svc.cluster.local}
TOKEN_URL=${TOKEN_URL:=https://token.tim-ramlot-gcp.jetstacker.net}

for CERT_FILE in "${CERT_FILES[@]}"; do
    if [ ! -f "$CERT_FILE" ]; then
        echo "Certificate file not found: $CERT_FILE" >&2
        exit 1
    fi
done

if [ -z "$TOKEN_URL" ]; then
    echo "TOKEN_URL is not set" >&2
    exit 1
fi

echo "> This certificate is mounted in this container:" >&2

openssl x509 -noout -text -in "$CERT_FILE" >&2
echo "" >&2

request_jwt() {
    audience=$1

    token=$(curl -s -X POST "$TOKEN_URL/token" \
        --key "$KEY_FILE" --cert <(cat "${CERT_FILES[@]}") \
        -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token_type=urn:ietf:params:oauth:token-type:tls-client-auth&audience=$audience")

    echo ">> I exchanged this certificate for this JWT token (using \"$TOKEN_URL/token\"):" >&2

    # Check for an error response
    if ! echo "$token" | jq -e "has(\"access_token\")" > /dev/null; then
        echo ">> Error: $token" >&2
        exit 1
    fi

    decodejwt=$(echo "$token" | jq .access_token | jq -R 'split(".") | .[1] | @base64d | fromjson')
    echo "$decodejwt" | jq >&2

    jwt=$(echo "$token" | jq .access_token | tr -d '"')
    issuer=$(echo "$decodejwt" | jq .iss)
    subject=$(echo "$decodejwt" | jq .sub)

    echo ">> This JWT is valid within the $issuer issuer (which is unique for your x509 CA)" >&2
    echo ">> This JWT is for the subject $subject" >&2
    echo ">> This JWT is for the audience $audience" >&2

    echo "$jwt"
}

GCLOUD_ENABLE=${GCLOUD_ENABLE:="false"}

if [ "$GCLOUD_ENABLE" == "true" ]; then
    GCLOUD_AUDIENCE=${GCLOUD_AUDIENCE:-}
    GCLOUD_SA=${GCLOUD_SA:-}
    GCLOUD_PROVIDER=${GCLOUD_PROVIDER:-}
    GCLOUD_PROJECT=${GCLOUD_PROJECT:-}

    if [ -z "$GCLOUD_AUDIENCE" ]; then
        echo "GCLOUD_AUDIENCE is not set" >&2
        exit 1
    fi

    if [ -z "$GCLOUD_SA" ]; then
        echo "GCLOUD_SA is not set" >&2
        exit 1
    fi

    if [ -z "$GCLOUD_PROVIDER" ]; then
        echo "GCLOUD_PROVIDER is not set" >&2
        exit 1
    fi

    if [ -z "$GCLOUD_PROJECT" ]; then
        echo "GCLOUD_PROJECT is not set" >&2
        exit 1
    fi

    echo ">> Requesting gcloud JWT token (audience: $GCLOUD_AUDIENCE)" >&2
    gcloud_jwt=$(request_jwt "$GCLOUD_AUDIENCE")

    mkdir -p ~/.gcloud/

    echo ">> Saving JWT in ~/.gcloud/gcloud-jwt-token" >&2
    echo "$gcloud_jwt" > ~/.gcloud/gcloud-jwt-token

    token_path="$(cd ~/.gcloud/ || exit; pwd)/gcloud-jwt-token"

    echo ">> Create credentials file for gcloud" >&2

    cat << EOF > gcloud.cred.json
{
  "type": "external_account",
  "audience": "$GCLOUD_PROVIDER",
  "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_url": "https://sts.googleapis.com/v1/token",
  "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/$GCLOUD_SA:generateAccessToken",
  "credential_source": {
    "file": "$token_path",
    "format": {
      "type": "text"
    }
  }
}
EOF

    gcloud auth login --cred-file=gcloud.cred.json
    gcloud config set project "$GCLOUD_PROJECT"
fi

AWS_ENABLE=${AWS_ENABLE:="false"}

if [ "$AWS_ENABLE" == "true" ]; then
    AWS_AUDIENCE=${AWS_AUDIENCE:-}
    AWS_ROLE=${AWS_ROLE:-}

    if [ -z "$AWS_AUDIENCE" ]; then
        echo "AWS_AUDIENCE is not set" >&2
        exit 1
    fi

    if [ -z "$AWS_ROLE" ]; then
        echo "AWS_ROLE is not set" >&2
        exit 1
    fi

    echo ">> Requesting AWS JWT token (audience: $AWS_AUDIENCE)" >&2
    aws_jwt=$(request_jwt "$AWS_AUDIENCE")

    mkdir -p ~/.aws

    echo ">> Saving JWT in ~/.aws/aws-jwt-token" >&2
    echo "$aws_jwt" > ~/.aws/aws-jwt-token
    
    token_path="$(cd ~/.aws/ || exit; pwd)/aws-jwt-token"

    cat << EOF > ~/.aws/config
[default]
role_arn=$AWS_ROLE
web_identity_token_file=$token_path
EOF
fi

AZURE_ENABLE=${AZURE_ENABLE:="false"}

if [ "$AZURE_ENABLE" == "true" ]; then
    AZURE_AUDIENCE=${AZURE_AUDIENCE:-}
    AZURE_APPLICATION_ID=${AZURE_APPLICATION_ID:-}
    AZURE_TENANT_ID=${AZURE_TENANT_ID:-}

    if [ -z "$AZURE_AUDIENCE" ]; then
        echo "AZURE_AUDIENCE is not set" >&2
        exit 1
    fi

    if [ -z "$AZURE_APPLICATION_ID" ]; then
        echo "AZURE_APPLICATION_ID is not set" >&2
        exit 1
    fi

    if [ -z "$AZURE_TENANT_ID" ]; then
        echo "AZURE_TENANT_ID is not set" >&2
        exit 1
    fi

    echo ">> Requesting Azure JWT token (audience: $AZURE_AUDIENCE)" >&2
    azure_jwt=$(request_jwt "$AZURE_AUDIENCE")

    mkdir -p ~/.azure

    echo ">> Saving JWT in ~/.azure/azure-jwt-token" >&2
    echo "$azure_jwt" > ~/.azure/azure-jwt-token

    az login --service-principal -u "$AZURE_APPLICATION_ID" --federated-token "$azure_jwt" --tenant "$AZURE_TENANT_ID"
fi

# AWS_ENABLE=true AWS_AUDIENCE=aws AWS_ROLE=<ROLE> workload.init.sh
# aws s3 ls

# AZURE_ENABLE=true AZURE_AUDIENCE=azure AZURE_APPLICATION_ID=<APPLICATION_ID> AZURE_TENANT_ID=<TENANT_ID> workload.init.sh
# az storage blob list --auth-mode login -c demo --account-name kubeconna24demo

# GCLOUD_ENABLE=true GCLOUD_AUDIENCE=gcloud GCLOUD_SA=<SA_NAME>@<PROJECT_NAME>.iam.gserviceaccount.com GCLOUD_PROVIDER=//iam.googleapis.com/projects/<PROJECT_ID>/locations/global/workloadIdentityPools/<POOL_NAME>/providers/<PROVIDER_NAME> GCLOUD_PROJECT=<PROJECT_NAME> workload.init.sh
# gcloud storage ls gs://demo-venafi-testbucket
