#!/bin/bash

if [ $# -ne 2 ]
then
    echo "ERROR: This script requires 2 arguments:"
    echo "  1. file path"
    echo "  2. text string"
    exit 1
fi

writefile="$1"
writestr="$2"

mkdir -p "$(dirname "$writefile")"
touch "$writefile"

if [ ! -f "$writefile" ]
then
    echo "ERROR: Could not create file $writefile"
    exit 1
fi

echo "$writestr" > "$writefile"
