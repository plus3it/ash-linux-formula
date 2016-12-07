#!/bin/sh
# Finding ID:	RHEL-07-040180
# Version:	RHEL-07-040180_rule
# SRG ID:	SRG-OS-000250-GPOS-00093
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must implement cryptography to protect the
#	integrity of Lightweight Directory Access Protocol (LDAP)
#	authentication communications.
#
# CCI-001453 
#    NIST SP 800-53 :: AC-17 (2) 
#    NIST SP 800-53A :: AC-17 (2).1 
#    NIST SP 800-53 Revision 4 :: AC-17 (2) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-040180"
diag_out "   The operating system must implement"
diag_out "   cryptography to protect the"
diag_out "   integrity of Lightweight Directory"
diag_out "   Access Protocol (LDAP)"
diag_out "   authentication communications."
diag_out "----------------------------------------"
