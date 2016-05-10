#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38596
# Finding ID:	V-38596
# Version:	RHEL-06-000078
# Finding Level:	Medium
#
#     The system must implement virtual address space randomization. 
#     Address space layout randomization (ASLR) makes it more difficult for 
#     an attacker to predict the location of attack code he or she has 
#     introduced into a process's address space during an attempt at ...
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38596"
diag_out "  The system must implement ASLR"
diag_out "----------------------------------"
