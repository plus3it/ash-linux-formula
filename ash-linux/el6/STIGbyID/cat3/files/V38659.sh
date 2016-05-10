#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38659
# Finding ID:	V-38659
# Version:	RHEL-06-000275
# Finding Level:	Low
#
#     The operating system must employ cryptographic mechanisms to protect 
#     information in storage. The risk of a system's physical compromise, 
#     particularly mobile systems such as laptops, places its data at risk 
#     of compromise. Encrypting this data mitigates the risk of its loss if 
#     the system is lost.
#
#  CCI: CCI-001019
#  NIST SP 800-53 :: MP-4 (1)
#  NIST SP 800-53A :: MP-4 (1).1
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38659"
diag_out "  The operating system must"
diag_out "  employ cryptographic mechanisms"
diag_out "  to protect information in"
diag_out "  storage."
diag_out "----------------------------------"
