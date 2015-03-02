#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Security identifiers:
# - CCE-26741-9
#
# Rule ID: accounts_password_reuse_limit
#
# Rule Summary: Limit Password Reuse
#
# Rule Text: Do not allow users to reuse recent passwords. The DoD and 
#            FISMA requirement is 24 passwords.  Preventing re-use of 
#            previous passwords helps ensure that a compromised password 
#            is not re-used by a user.
#
#################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "-----------------------------------"
diag_out "SCAP Recommendation: "
diag_out "  Set password-reuse policy to '24'"
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "-----------------------------------"

