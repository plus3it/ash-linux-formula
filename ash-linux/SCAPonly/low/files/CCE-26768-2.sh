#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID:
# - root_path_no_groupother_writable
#
# Security identifiers:
# - CCE-26768-2
#
# Rule Summary: Ensure that root's path does not include world
#               or group-writable directories
#
# Rule Text: Ensure that write permissions are disabled for group and 
#            other on all directories in the root user's PATH. Such 
#            entries increase the risk that root could execute code 
#            provided by unprivileged users, and potentially malicious 
#            code.
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "-----------------------------------"
diag_out "SCAP Recommendation: "
diag_out "  No group- or world-writable"
diag_out "  directories in root user's path"
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "-----------------------------------"
