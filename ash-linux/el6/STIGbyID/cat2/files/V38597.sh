#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38597
# Finding ID:	V-38597
# Version:	RHEL-06-000079
# Finding Level:	Medium
#
#     The system must limit the ability of processes to have simultaneous 
#     write and execute access to memory. ExecShield uses the segmentation 
#     feature on all x86 systems to prevent execution in memory higher than 
#     a certain address. It writes an address as a limit in the code 
#     segment descriptor, to control ...
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38597"
diag_out "  Enable the kernel exec-shield to"
diag_out "  prevent certain types of memory-"
diag_out "  based system attacks"
diag_out "----------------------------------"
