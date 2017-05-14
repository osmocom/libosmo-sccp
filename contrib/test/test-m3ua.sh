#!/bin/sh

# this script executes m3ua-testtool against osmo-stp.  It assumes that
# it is called from within libosmo-sccp/contrib/test and also assumes
# that adjacent to the libosmo-sccp, there's a check-out of
# git://git.osmocom.org/nplab/m3ua-testtool

# the top of the libosmo-sccp git repository
TOPDIR=../../

# the directory in which we can find the osmo-stp binary
STP_DIR=$TOPDIR/stp

# the directory in which we can find the m3ua-testtool.git
M3UA_DIR=$TOPDIR/../m3ua-testtool

# osmo-stp config file, used from CWD
STP_CONFIG=./osmo-stp.cfg

# we're pesudo-root but inherit the path from a non-root user
PATH=/sbin:/usr/sbin:$PATH

# set up the ip addresses
ip link set lo up
ip addr add 172.18.0.2/32 dev lo
ip addr add 172.18.0.200/32 dev lo

$STP_DIR/osmo-stp -c $STP_CONFIG &
STP_PID=$!
(cd $M3UA_DIR && ./run-all-sgp-tests)
kill $!
