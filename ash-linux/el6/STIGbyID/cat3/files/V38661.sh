#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38661
# Finding ID:	V-38661
# Version:	RHEL-06-000276
# Finding Level:	Low
#
#     The operating system must protect the confidentiality and integrity 
#     of data at rest. The risk of a system's physical compromise, 
#     particularly mobile systems such as laptops, places its data at risk 
#     of compromise. Encrypting this data mitigates the risk of its loss if 
#     the system is lost.
#
#  CCI: CCI-001199
#  NIST SP 800-53 :: SC-28
#  NIST SP 800-53A :: SC-28.1
#  NIST SP 800-53 Revision 4 :: SC-28
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38661"
diag_out "  The operating system must"
diag_out "  protect the confidentiality and"
diag_out "  integrity of data at rest."
diag_out "----------------------------------"
