#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-57569
# Finding ID:	V-57569
# Version:	RHEL-06-000528
# Finding Level:	Medium
#
#     Allowing users to execute binaries from world-writable 
#     directories such as "/tmp" should never be necessary in normal 
#     operation and can expose the system to potential compromise.
#
# CCI: CCI-000381
# NIST SP 800-53 :: CM-7
# NIST SP 800-53A :: CM-7.1 (ii)
# NIST SP 800-53 Revision 4 :: CM-7 a
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-57569"
diag_out "  The '/tmp' filesystem must be"
diag_out "  mounted with the noexec mount"
diag_out "  option set"
diag_out "----------------------------------"

