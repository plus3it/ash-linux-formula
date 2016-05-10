#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-51369
# Finding ID:	V-51369
# Version:	RHEL-06-000023
# Finding Level:	Low
#
#     The system must use a Linux Security Module configured to limit the 
#     privileges of system services. Setting the SELinux policy to 
#     "targeted" or a more specialized policy ensures the system will 
#     confine processes that are likely to be targeted for exploitation, 
#     such as network or system services.
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
diag_out "STIG Finding ID: V-51369"
diag_out "  The system must use a Linux"
diag_out "  Security Module configured to"
diag_out "  limit the privileges of system"
diag_out "  services."
diag_out "----------------------------------"
