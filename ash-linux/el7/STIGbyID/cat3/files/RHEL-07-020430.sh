#!/bin/sh
#
# STIG URL:
# Finding ID:	RHEL-07-020430
# Version:	RHEL-07-020430_rule
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#     Manual page files must have mode 0644 or less permissive.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################

diag_out() {
   echo "${1}"
}

diag_out "---------------------------------------------"
diag_out "STIG Finding ID: RHEL-07-020430"
diag_out "   Manual page files must have mode 0644 or "
diag_out "   less permissive."
diag_out "---------------------------------------------"
