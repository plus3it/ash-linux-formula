#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38653
# Finding ID:	V-38653
# Version:	RHEL-06-000341
# Finding Level:	High
#
#     The snmpd service must not use a default password. Presence of the 
#     default SNMP password enables querying of different system aspects 
#     and could result in unauthorized knowledge of the system.
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38653"
diag_out "  SNMPD must not use a default"
diag_out "  password"
diag_out "----------------------------------"

