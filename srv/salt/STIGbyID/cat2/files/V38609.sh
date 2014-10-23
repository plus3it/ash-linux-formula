#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38609
# Finding ID:	V-38609
# Version:	RHEL-06-000223
# Finding Level:	Medium
#
#     The TFTP service must not be running. Disabling the "tftp" service 
#     ensures the system is not acting as a tftp server, which does not 
#     provide encryption or authentication.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38609"
diag_out "  The tftp service must not be"
diag_out "  running"
diag_out "----------------------------------"
