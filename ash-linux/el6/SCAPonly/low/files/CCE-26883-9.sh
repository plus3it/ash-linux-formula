#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID:
# - 
#
# Security identifiers:
# - CCE-26883-9
#
# Rule Summary: 
#
# Rule Text:
#
#################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "SCAP Recommendation: "
diag_out "  Already coverd by EL6u6 STIG ID"
diag_out "  'V-38535'"
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "----------------------------------"

