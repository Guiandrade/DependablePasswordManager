#!/bin/sh

# DependablePasswordManagerClient script that takes two arguments (number of clients and number of servers) to initialize clients,
# each one on a separate terminal, and to connect them to all the server replicas.

x=1
while [ $x -le $1 ]
do
  gnome-terminal -e "bash -c \"mvn compile exec:java -Dexec.args='"$x" "$2"'; exec bash\""
  x=$(( $x + 1 ))
done
