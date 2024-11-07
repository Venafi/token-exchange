#!/usr/bin/env bash

set -eu -o pipefail

request_jwt() {
    audience=$1

    token=$(spire-agent api fetch jwt -audience "$audience" -output json -socketPath /var/run/secrets/workload-spiffe-uds/socket | jq -r '.[0].svids[0].svid')

    echo ">> Fetched JWT from SPIFFE workload API" >&2

    decodejwt=$(echo "$token" | jq -R 'split(".") | .[1] | @base64d | fromjson')

    issuer=$(echo "$decodejwt" | jq .iss)
    subject=$(echo "$decodejwt" | jq .sub)

    echo ">> JWT issuer:   $issuer" >&2
    echo ">> JWT subject:  $subject" >&2
    echo ">> JWT audience: $audience" >&2

    echo "$token"
}

AWS_AUDIENCE=aws
AZURE_AUDIENCE=azure
GCLOUD_AUDIENCE=gcloud

echo ">> Requesting AWS JWT token (audience: $AWS_AUDIENCE)" >&2

AWS_ROLE="<ROLE>"

cat << EOF > ~/.aws/config
[default]
role_arn=$AWS_ROLE
web_identity_token_file=/root/.aws/aws-jwt-token
EOF
request_jwt "$AWS_AUDIENCE" > /root/.aws/aws-jwt-token

echo ">> Completed login for AWS" >&2
echo "" >&2

sleep 2

echo ">> Requesting gcloud JWT token (audience: $GCLOUD_AUDIENCE)" >&2

GCLOUD_PROVIDER="//iam.googleapis.com/projects/<PROJECT_ID>/locations/global/workloadIdentityPools/<POOL_NAME>/providers/<PROVIDER_NAME>"
GCLOUD_SA="<SA_NAME>@<PROJECT_NAME>.iam.gserviceaccount.com"
GCLOUD_PROJECT="<PROJECT_NAME>"

cat << EOF > /root/.cloud/gcloud.cred.json
{
  "type": "external_account",
  "audience": "$GCLOUD_PROVIDER",
  "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_url": "https://sts.googleapis.com/v1/token",
  "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/$GCLOUD_SA:generateAccessToken",
  "credential_source": {
    "file": "/root/.gcloud/gcloud.cred.json",
    "format": {
      "type": "text"
    }
  }
}
EOF
request_jwt "$GCLOUD_AUDIENCE" > /root/.gcloud/gcloud-jwt-token

gcloud auth login --brief --cred-file=/root/.gcloud/gcloud.cred.json > /tmp/gcloud-login-output.txt
gcloud config set project $GCLOUD_PROJECT >/dev/null

echo ">> Completed login for GCP" >&2
echo "" >&2

sleep 2

echo ">> Requesting Azure JWT token (audience: $AZURE_AUDIENCE)" >&2

AZURE_APPLICATION_ID="<APPLICATION_ID>"
AZURE_TENANT_ID="<TENANT_ID>"

azure_jwt=$(request_jwt "$AZURE_AUDIENCE")

az login --service-principal -u $AZURE_APPLICATION_ID --federated-token "$azure_jwt" --tenant $AZURE_TENANT_ID > /tmp/azure-login-output.txt

echo ">> Completed login for Azure" >&2
echo "" >&2

sleep 2
