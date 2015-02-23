#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID:
# - sysctl_net_ipv6_conf_default_accept_ra
#
# Security identifiers:
# - CCE-27164-3
#
# Rule Summary: Disable Accepting IPv6 Router Advertisements
#
# Rule Text: An illicit router advertisement message could result in a 
#            man-in-the-middle attack. This rule should be present in
#            case of intentional or accidental activation of IPv6
#            networking components.
#
#################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "-----------------------------------"
diag_out "SCAP Recommendation: "
diag_out "  Disable acceptance of IPv6 router"
diag_out "  advertisement messages"
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "-----------------------------------"

