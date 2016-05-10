#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Security identifiers:
# - CCE-26872-2
#
# Rule ID: no_files_unowned_by_group
#
# Rule Summary: Ensure All Files Are Owned by a Group
#
# Rule Text: If any files are not owned by a group, then the cause of 
#            their lack of group-ownership should be investigated. 
#            Following this, the files should be deleted or assigned to 
#            an appropriate group.
#
#            Unowned files do not directly imply a security problem, but 
#            they are generally a sign that something is amiss. They may 
#            be caused by an intruder, by incorrect software 
#            installation or draft software removal, or by failure to 
#            remove all files belonging to a deleted account. The files 
#            should be repaired so they will not cause problems when 
#            accounts are created in the future, and the cause should be 
#            discovered and addressed.
#
#################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "SCAP Recommendation: "
diag_out "  Ensure no files lack a group"
diag_out "  owner mapped in /etc/group"
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "----------------------------------"

