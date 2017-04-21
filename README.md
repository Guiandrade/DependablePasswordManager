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

1) Go to the keyStore folder on the terminal and run the following commands:
      - mvn compile
      - mvn exec:java
      (On the number of keys wanted please input at least 3)
2) Go to the dependablePasswordManagerServer folder on the terminal and run the following commands (for 3 servers ):
      - sh servers.sh 3
3) Go to the dependablePasswordManagerClient folder on the terminal and run the following command (for 3 clients and 3 servers):
      - sh clients.sh 3 3

Instructions Stage 2:

      Projecto:
            - Em java (ou shell ou outra coisa qualquer) fazer um script para lançar os N servidores:
            - (1,N)  --> 1 escritor, N leitores(server)

Nota : Pode-se se saltar o step 1 do enunciado da parte 2

      Relatório:
            - Estender e explicar demos/testes (mostrar que está bom contra ameaças)
            - Referencia para cada teste(quando falamos de uma ameaça, apontamos para o teste que demonstra que está protegido)
