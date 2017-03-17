# DependablePasswordManager
The goal of this project is to  implement a  distributed password manager with dependability guarantee.

[Stage 1] (https://fenix.tecnico.ulisboa.pt/downloadFile/1970943312288157/SEC-1617%20-%20project%20-%20stage%201.pdf)

Before testing if remote object calling is working, please open a terminal window and write the following :

(For linux)
rmiregistry &

(For Windows)
start rmiregistry 

To Run:

1) Go to the keyStore folder on the terminal and run the following commands:
      - mvn compile
      - mvn exec:java
      (On the number of keys wanted please input at least 1)
2) Go to the dependablePasswordManagerServer folder on the terminal and run the following commands:
      - mvn compile
      - mvn exec:java
3) Go to the dependablePasswordManagerClient folder on the terminal and run the following commands:
      - mvn compile
      - mvn exec:java
      
