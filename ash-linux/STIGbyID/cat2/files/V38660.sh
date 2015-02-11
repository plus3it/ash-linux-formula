#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38660
# Finding ID:	V-38660
# Version:	RHEL-06-000340
# Finding Level:	Medium
#
#     The snmpd service must use only SNMP protocol version 3 or newer. 
#     Earlier versions of SNMP are considered insecure, as they potentially 
#     allow unauthorized access to detailed system management information.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38660"
diag_out "  The SNMP services must use the"
diag_out "  version 3 or newer protocols"
diag_out "----------------------------------"

