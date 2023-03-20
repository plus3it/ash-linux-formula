#!/bin/sh
# STIG ID:	RHEL-07-030819
# Rule ID:	SV-204559r603261_rule
# Vuln ID:	V-204559
# SRG ID:	SRG-OS-000471-GPOS-00216
# Finding Level:	medium
#
# Rule Summary:
#	The operating system must audit all uses of the
#   `create_module` syscall
#
# CCI-000172
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-030819"
diag_out "   All uses of the create_module command"
diag_out "   must be audited."
diag_out "----------------------------------------"
