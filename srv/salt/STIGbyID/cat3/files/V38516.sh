#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38516
# Finding ID:	V-38516
# Version:	RHEL-06-000126
# Finding Level:	Low
#
#     The Reliable Datagram Sockets (RDS) protocol must be disabled unless 
#     required. Disabling RDS protects the system against exploitation of 
#     any flaws in its implementation.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38516"
diag_out "  Reliable Datagram Sockets (RDS)"
diag_out "  protocol must be disabled"
diag_out "----------------------------------"
