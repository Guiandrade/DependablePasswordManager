#!/bin/sh

# Script to setup keyStore with 5 keyPairs, 3 servers and 3 clients on the DependablePasswordManager Project

# Create 5 KeyPairs
cd keyStore
sh keyGen.sh 5

# Create 3 servers
cd ..
cd dependablePasswordManager
sh servers.sh 3

# Create 3 clients
cd ..
cd dependablePasswordManagerClient
sh clients.sh 3 3
