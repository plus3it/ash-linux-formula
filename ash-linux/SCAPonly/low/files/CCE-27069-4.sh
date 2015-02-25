#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID:
# - configure_logwatch_splithosts
#
# Security identifiers:
# - CCE-27069-4
#
# Rule Summary: Configure logwatch SplitHosts line
#
# Rule Text: If SplitHosts is set, Logwatch will separate entries by 
#            hostname. This makes the report longer but significantly 
#            more usable. If it is not set, then Logwatch will not 
#            report which host generated a given log entry, and that 
#            information is almost always necessary.
#
#################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "-----------------------------------"
diag_out "SCAP Recommendation: "
diag_out "  Enable 'SplitHosts' option in"
diag_out "  the 'logwatch' service."
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "-----------------------------------"
