#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38611
# Finding ID:	V-38611
# Version:	RHEL-06-000234
# Finding Level:	Medium
#
#     The SSH daemon must ignore .rhosts files. SSH trust relationships 
#     mean a compromise on one host can allow an attacker to move trivially 
#     to other hosts.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38611"
diag_out "  The SSH daemon must ignore all"
diag_out "  .rhosts files"
diag_out "----------------------------------"
