#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38581
# Finding ID:	V-38581
# Version:	RHEL-06-000066
# Finding Level:	Medium
#
#     The system boot loader configuration file(s) must be group-owned by 
#     root. The "root" group is a highly-privileged group. Furthermore, the 
#     group-owner of this file should not have any access privileges anyway.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38581"
diag_out "  system boot-loader config files"
diag_out "  must be group-owned by the root"
diag_out "  group"
diag_out "----------------------------------"
