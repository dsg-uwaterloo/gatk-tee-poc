#!/bin/bash

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <server hotsname> <datafile> <scriptfile> <secure> <number of iterations>"
    exit 1
fi

host=$1
datafile=$2
scriptfile=$3
secure=$4
iterations=$5

for i in {1..$iterations}; do
    echo "Iteration ${i}:\n" | tee -a client.out
    if [ "$secure" = "true" ]; then
        python client.py -sh "$host" -d test/"$datafile" -gs test/"$scriptfile" -r results 2>&1 | tee -a client.out
    else
        python client.py -sh "$host" -d test/"$datafile" -gs test/"$scriptfile" -r results -is 2>&1 | tee -a client.out
    fi
    echo "\n" | tee -a client.out
done