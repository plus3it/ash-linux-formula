#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38515
# Finding ID:	V-38515
# Version:	RHEL-06-000125
# Finding Level:	Medium
#
#     The Stream Control Transmission Protocol (SCTP) must be disabled 
#     unless required. Disabling SCTP protects the system against 
#     exploitation of any flaws in its implementation.
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38515"
diag_out "  The Stream Control Transmission"
diag_out "  Protocol (SCTP) must be disabled"
diag_out "----------------------------------"
