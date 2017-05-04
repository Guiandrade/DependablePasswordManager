# DependablePasswordManager
The goal of this project is to  implement a  distributed password manager with dependability guarantee.

[Stage 1](https://fenix.tecnico.ulisboa.pt/downloadFile/1970943312288157/SEC-1617%20-%20project%20-%20stage%201.pdf)

[Stage 2](https://fenix.tecnico.ulisboa.pt/downloadFile/845043405450969/SEC-1617%20project%20-%20stage%202.pdf)

Before testing if remote object calling is working, please open a terminal window and write the following :

(For linux)
rmiregistry &

(For Windows)
start rmiregistry

To Run:

1) Go to the project folder on the terminal and run the following command (creates 1 client and 4 servers):
      - sh autoSetup.sh

2) Insert KeyStore password "sec" when prompted on each Server.      

