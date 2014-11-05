#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38578
# Finding ID:	V-38578
# Version:	RHEL-06-000201
# Finding Level:	Low
#
#     The audit system must be configured to audit changes to the 
#     /etc/sudoers file. The actions taken by system administrators should 
#     be audited to keep a record of what was executed on the system, as 
#     well as, for accountability purposes.
#
#  CCI: CCI-000172
#  NIST SP 800-53 :: AU-12 c
#  NIST SP 800-53A :: AU-12.1 (iv)
#  NIST SP 800-53 Revision 4 :: AU-12 c
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38578"
diag_out "  Audit system must log changes"
diag_out "  to the /etc/sudoers file"
diag_out "----------------------------------"
