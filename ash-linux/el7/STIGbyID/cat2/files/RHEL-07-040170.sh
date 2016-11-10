#!/bin/sh
# Finding ID:	RHEL-07-040170
# Version:	RHEL-07-040170_rule
# SRG ID:	SRG-OS-000023-GPOS-00006
# Finding Level:	medium
# 
# Rule Summary:
#	The Standard Mandatory DoD Notice and Consent Banner must be
#	displayed immediately prior to, or as part of, remote access
#	logon prompts.
#
# CCI-000048 
# CCI-000050 
# CCI-001384 
# CCI-001385 
# CCI-001386 
# CCI-001387 
# CCI-001388 
#    NIST SP 800-53 :: AC-8 a 
#    NIST SP 800-53A :: AC-8.1 (ii) 
#    NIST SP 800-53 Revision 4 :: AC-8 a 
#    NIST SP 800-53 :: AC-8 b 
#    NIST SP 800-53A :: AC-8.1 (iii) 
#    NIST SP 800-53 Revision 4 :: AC-8 b 
#    NIST SP 800-53 :: AC-8 c 
#    NIST SP 800-53A :: AC-8.2 (i) 
#    NIST SP 800-53 Revision 4 :: AC-8 c 1 
#    NIST SP 800-53 :: AC-8 c 
#    NIST SP 800-53A :: AC-8.2 (ii) 
#    NIST SP 800-53 Revision 4 :: AC-8 c 2 
#    NIST SP 800-53 :: AC-8 c 
#    NIST SP 800-53A :: AC-8.2 (ii) 
#    NIST SP 800-53 Revision 4 :: AC-8 c 2 
#    NIST SP 800-53 :: AC-8 c 
#    NIST SP 800-53A :: AC-8.2 (ii) 
#    NIST SP 800-53 Revision 4 :: AC-8 c 2 
#    NIST SP 800-53 :: AC-8 c 
#    NIST SP 800-53A :: AC-8.2 (iii) 
#    NIST SP 800-53 Revision 4 :: AC-8 c 3 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-040170"
diag_out "   The Standard Mandatory DoD Notice"
diag_out "   and Consent Banner must be displayed"
diag_out "   immediately prior to, or as part of,"
diag_out "   remote access logon prompts."
diag_out "----------------------------------------"
