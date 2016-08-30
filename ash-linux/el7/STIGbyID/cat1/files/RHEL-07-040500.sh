#!/bin/bash
#
# Finding ID:	RHEL-07-040500
# Version:	RHEL-07-040500_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	high
#
# Rule Summary:
#	The Trivial File Transfer Protocol (TFTP) server package
#	must not be installed if not required for operational support.
#
# CCI-000368
# CCI-000318
# CCI-001812
# CCI-001813
# CCI-001814
#    NIST SP 800-53 :: CM-6 c
#    NIST SP 800-53A :: CM-6.1 (v)
#    NIST SP 800-53 Revision 4 :: CM-6 c
#    NIST SP 800-53 :: CM-3 e
#    NIST SP 800-53A :: CM-3.1 (v)
#    NIST SP 800-53 Revision 4 :: CM-3 f
#    NIST SP 800-53 Revision 4 :: CM-11 (2)
#    NIST SP 800-53 Revision 4 :: CM-5 (1)
#    NIST SP 800-53 Revision 4 :: CM-5 (1)
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-040500"
diag_out "   The Trivial File Transfer Protocol"
diag_out "   (TFTP) server package must only be"
diag_out "   installed if required for operational"
diag_out "   support."
diag_out "----------------------------------------"

