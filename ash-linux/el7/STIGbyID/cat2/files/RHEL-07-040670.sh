#!/bin/sh
# Finding ID:	RHEL-07-040670
# Version:	RHEL-07-040670_rule
# SRG ID:	SRG-OS-000364-GPOS-00151
# Finding Level:	medium
# 
# Rule Summary:
#	The SSH daemon must not permit Kerberos authentication unless needed.
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
diag_out "STIG Finding ID: RHEL-07-040670"
diag_out "   The SSH daemon must not permit"
diag_out "   Kerberos authentication unless"
diag_out "   needed."
diag_out "----------------------------------------"
