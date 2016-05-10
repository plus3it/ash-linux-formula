#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38540
# Finding ID:	V-38540
# Version:	RHEL-06-000182
# Finding Level:	Low
#
#     The audit system must be configured to audit modifications to the 
#     systems network configuration. The network environment should not be 
#     modified by anything other than administrator action. Any change to 
#     network parameters should be audited.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "-----------------------------------"
diag_out "STIG Finding ID: V-38540"
diag_out "  Audit system must be configured"
diag_out "  to audit modifications to the"
diag_out "  systems network configuration"
diag_out "-----------------------------------"
