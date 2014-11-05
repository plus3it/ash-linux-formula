#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38675
# Finding ID:	V-38675
# Version:	RHEL-06-000308
# Finding Level:	Low
#
#     Process core dumps must be disabled unless needed. A core dump 
#     includes a memory image taken at the time the operating system 
#     terminates an application. The memory image could contain sensitive 
#     data and is generally useful only for developers trying to debug
#     problems.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38675"
diag_out "  Process core dumps should be"
diag_out "  disabled"
diag_out "----------------------------------"
