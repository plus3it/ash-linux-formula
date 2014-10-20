#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38514
# Finding ID:	V-38514
# Version:	RHEL-06-000124
# Finding Level:	Medium
#
#     The Datagram Congestion Control Protocol (DCCP) must be disabled 
#     unless required. Disabling DCCP protects the system against 
#     exploitation of any flaws in its implementation.
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38514"
diag_out "  The Datagram Congestion Control"
diag_out "  Protocol (DCCP) must be disabled"
diag_out "  unless specifically required"
diag_out "----------------------------------"
