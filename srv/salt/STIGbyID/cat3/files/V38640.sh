#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38640
# Finding ID:	V-38640
# Version:	RHEL-06-000261
# Finding Level:	Low
#
#     The Automatic Bug Reporting Tool (abrtd) service must not be running. 
#     Mishandling crash data could expose sensitive information about 
#     vulnerabilities in software executing on the local machine, as well 
#     as sensitive information from within a process's address space or
#     registers.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38640"
diag_out "  Automatic Bug Reporting Tool"
diag_out "  (abrtd) service must not be"
diag_out "  running"
diag_out "----------------------------------"
