#!/bin/sh
# Finding ID:	RHEL-07-031010
# Version:	RHEL-07-031010_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The rsyslog daemon must not accept log messages from other
#	servers unless the server is being used for log aggregation.
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
diag_out "STIG Finding ID: RHEL-07-031010"
diag_out "   The rsyslog daemon must not accept"
diag_out "   log messages from other servers"
diag_out "   unless the server is being used for"
diag_out "   log aggregation."
diag_out "----------------------------------------"
