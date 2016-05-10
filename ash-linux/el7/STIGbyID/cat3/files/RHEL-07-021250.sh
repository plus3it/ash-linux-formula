#!/bin/sh
#
# STIG URL:
# Finding ID:	RHEL-07-021250
# Version:	RHEL-07-021250_rule
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#     The system must use a separate file system for /var.
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
diag_out "STIG Finding ID: RHEL-07-021250"
diag_out "   The system must use a separate filesystem"
diag_out "   for /var."
diag_out "---------------------------------------------"
