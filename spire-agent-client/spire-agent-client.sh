#! /bin/sh

set -eu -o pipefail

echo "+ Fetching X.509 SVID"

mkdir /tmp/svid

/opt/spire/bin/spire-agent api fetch x509 -socketPath /spiffe/spiffe.sock -write /tmp/svid/

echo "+ X.509 SVID"

cat /tmp/svid/svid.0.pem

echo "+ X.509 Bundle"

cat /tmp/svid/bundle.0.pem

echo "+ Fetching JWT SVID"

# We redirect the output to a file and print a success message instead, to avoid printing a secret (the JWT) to logs
/opt/spire/bin/spire-agent api fetch jwt -socketPath /spiffe/spiffe.sock -audience abc123,testaud > /tmp/jwtsvid && echo "successfully fetched JWT svid"

sleep 31536000
