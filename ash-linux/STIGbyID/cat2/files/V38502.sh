#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38502
# Finding ID:	V-38502
# Version:	RHEL-06-000033
# Finding Level:	Medium
#
#     The /etc/shadow file must be owned by root. The "/etc/shadow" file 
#     contains the list of local system accounts and stores password 
#     hashes. Protection of this file is critical for system security. 
#     Failure to give ownership of this file to root ...
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38502"
diag_out "  The /etc/shadow file must be"
diag_out "  owned by the root user"
diag_out "----------------------------------"
