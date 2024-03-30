#!/bin/bash

openssl req -x509 -newkey rsa:4096 \
    -keyout key.pem -out cert.pem -noenc \
    -days 3650 -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"
