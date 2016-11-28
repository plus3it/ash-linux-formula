#!/bin/sh
# Finding ID:	RHEL-07-040100
# Version:	RHEL-07-040100_rule
# SRG ID:	SRG-OS-000096-GPOS-00050
# Finding Level:	medium
# 
# Rule Summary:
#	The host must be configured to prohibit or restrict the use
#	of functions, ports, protocols, and/or services, as defined
#	in the Ports, Protocols, and Services Management Component
#	Local Service Assessment (PPSM CLSA) and vulnerability
#	assessments.
#
# CCI-000382 
# CCI-002314 
#    NIST SP 800-53 :: CM-7 
#    NIST SP 800-53A :: CM-7.1 (iii) 
#    NIST SP 800-53 Revision 4 :: CM-7 b 
#    NIST SP 800-53 Revision 4 :: AC-17 (1) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-040100"
diag_out "----------------------------------------"
