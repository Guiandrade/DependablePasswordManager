#!/bin/sh

# Script to setup keyStore with 5 keyPairs, 3 servers and 3 clients on the DependablePasswordManager Project

# Create 3 servers
cd dependablePasswordManager
sh servers.sh 3

# Create 3 clients
cd ..
cd dependablePasswordManagerClient
sh clients.sh 3 3
