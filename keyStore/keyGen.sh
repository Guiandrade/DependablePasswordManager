#!/bin/sh

# keyStore script that takes one argument (number of keyPairs) to generate KeyPairs

gnome-terminal -e "bash -c \"mvn compile exec:java -Dexec.args='"$1"'; exec bash\""
