#!/bin/bash

CGO_ENABLED=0 GOARM=6 GOARCH=arm go build -o server .

scp ./server tramlot@192.168.0.4:/home/tramlot/server
scp ./key.pem tramlot@192.168.0.4:/home/tramlot/key.pem
scp ./cert.pem tramlot@192.168.0.4:/home/tramlot/cert.pem
