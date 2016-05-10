#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38546
# Finding ID:	V-38546
# Version:	RHEL-06-000098
# Finding Level:	Medium
#
#     The IPv6 protocol handler must not be bound to the network stack 
#     unless needed. Any unnecessary network stacks - including IPv6 - 
#     should be disabled, to reduce the vulnerability to exploitation.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38546"
diag_out "  Disable all un-needed network"
diag_out "  stacks (e.g. IPv6)"
diag_out "----------------------------------"
