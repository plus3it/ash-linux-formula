#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID:
# - network_disable_zeroconf
#
# Security identifiers:
# - CCE-27151-0
#
# Rule Summary: Disable Zeroconf Networking
#
# Rule Text: Zeroconf networking allows the system to assign itself an 
#            IP address and engage in IP communication without a 
#            statically-assigned address or even a DHCP server. 
#            Automatic address assignment via Zeroconf (or DHCP) is not 
#            recommended.
#
#################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "SCAP Recommendation: "
diag_out "  Disable ZeroConf networking"
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "----------------------------------"

