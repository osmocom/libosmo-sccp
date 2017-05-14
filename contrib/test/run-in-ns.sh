#!/bin/sh

# small helper script to run the specified command inside a network
# namespace while remapping the real PID to root inside the namespace,
# so the program inside the namespace can do things like setting
# interface addresses

if [ $# -eq 0 ]; then
	echo "You have to specify the command you want to execute in the new namespace"
	exit 1
fi

unshare --map-root-user --user -i -m -p -f -u -U -n $1
