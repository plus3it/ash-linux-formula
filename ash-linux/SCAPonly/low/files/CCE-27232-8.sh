#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID:
# - network_ipv6_disable_rpc
#
# Security identifiers:
# - CCE-27232-8
#
# Rule Text: RPC services for NFSv4 try to load transport modules for
#            udp6 and tcp6 by default, even if IPv6 has been disabled in
#            /etc/modprobe.d. To prevent RPC services such as rpc.mountd
#            from attempting to start IPv6 network listeners, remove or
#            comment out the following two lines in /etc/netconfig:
#
#################################################################


# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "-----------------------------------"
diag_out "SCAP Recommendation: "
diag_out "  Disable udp6 and tcp6 entries in"
diag_out "  rpc.mountd's /etc/netconfig file"
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "-----------------------------------"

