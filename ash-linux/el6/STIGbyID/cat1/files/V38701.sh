#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38701
# Finding ID:	V-38701
# Version:	RHEL-06-000338
# Finding Level:	High
#
#     The TFTP daemon must operate in secure mode which provides access 
#     only to a single directory on the host file system. Using the "-s" 
#     option causes the TFTP service to only serve files from the given 
#     directory. Serving files from an intentionally specified directory 
#     reduces the risk of sharing files which should ...
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38701"
diag_out "Chroot TFTP service (if installed)"
diag_out "----------------------------------"
