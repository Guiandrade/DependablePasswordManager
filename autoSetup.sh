#!/bin/sh

# Script to setup keyStore with 5 keyPairs, 3 servers and 3 clients on the DependablePasswordManager Project

# Create 4 servers
cd dependablePasswordManager
sh servers.sh 4

# Create 4 clients
cd ..
cd dependablePasswordManagerClient
sh clients.sh 1 4
