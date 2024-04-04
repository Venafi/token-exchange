#!/bin/bash

# Run this on the RPI

./server

ssh -p 443 -R0:localhost:7000 tcp@a.pinggy.io

ssh -p 443 -R0:localhost:8000 a.pinggy.io
