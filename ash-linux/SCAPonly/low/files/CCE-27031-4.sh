#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID:
# - umask_for_daemons
#
# Security identifiers:
# - CCE-26974-6
#
# Rule Summary: Set Daemon Umask
#
# Rule Text: Setting the umask to too restrictive a setting can cause 
#            serious errors at runtime. Many daemons on the system 
#            already individually restrict themselves to a umask of 077 
#            in their own init scripts.
#     
#            The umask influences the permissions assigned to files 
#            created by a process at run time. An unnecessarily 
#            permissive umask could result in files being created with 
#            insecure permissions.
#
#################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "SCAP Recommendation: "
diag_out "  Already coverd by EL6u6 STIG ID"
diag_out "  'V-38642'"
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "----------------------------------"

