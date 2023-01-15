#!/bin/bash

if [ $# -ne 1 ]; then
	echo "usage: fsmanifest_to_sha512 <fsmanifest>" 1>&2
	exit 1
fi

grep -e '^[^	]' -e '^	Hash' "$1" | sed 's/:$//' | while IFS= read -r i; do
	if [[ "$i" == '	Hash'* ]]; then
		echo ${i#*:}"  $PREV_LINE"
	fi
	PREV_LINE="$i"
done
