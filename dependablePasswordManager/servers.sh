#!/bin/sh

# DependablePasswordManager script that takes one argument (number of servers) to initialize servers,
# each one on a separate terminal.

x=1
while [ $x -le $1 ]
do
  gnome-terminal -e "bash -c \"mvn compile exec:java -Dexec.args="808"$x""; exec bash\""
  x=$(( $x + 1 ))
done

