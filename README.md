# DependablePasswordManager
The goal of this project is to  implement a  distributed password manager with dependability guarantees.

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

<<<<<<< HEAD
2) Insert KeyStore spassword "sec" when prompted on each Client.

Other commands:

1) To generate N key pairs:
cd keyStore
sh keyGen.sh (N)

2) To change the number of servers and clients in autoSetup.sh:
Change in line 7 from "sh servers.sh 4" to "sh servers.sh (new num servers)"
Change in line 12 from "sh clients.sh 1 4" to "sh clients.sh (new num clients) (new num servers)"

3) To start manually N servers:
cd dependablePasswordManager
sh servers.sh (N)

4) To start manually N clients:
cd dependablePasswordManagerClient
sh clients.sh (N) (num servers)

5) To start a client with a specific client id
mvn compile exec:java -Dexec.args="(client id) (num servers)"

6) To run client tests:
(located at: dependablePasswordManagerClient/src/test/java/pt/ulisboa/ist/sec/ClientTest.java)
cd dependablePasswordManager
mvn compile test

6) To run server tests:
(located at: dependablePasswordManagerClient/src/test/java/pt/ulisboa/ist/sec/ServerTest.java)
cd dependablePasswordManagerClient
mvn compile test
=======
2) Insert KeyStore password "sec" when prompted on each Server.      
>>>>>>> 1d42f2a865301a25738af9b4631849ac16390b47

