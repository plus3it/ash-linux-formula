#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID:
# - homedir_perms_no_groupwrite_worldread
#
# Security identifiers:
# - CCE-26981-1
#
# Rule Summary: Ensure that User Home Directories are not Group-Writable or 
#               World-Readable.
#
# Rule Text: User home directories contain many configuration files 
#            which affect the behavior of a user's account. No user 
#            should ever have write permission to another user's home 
#            directory. Group shared directories can be configured in 
#            sub-directories or elsewhere in the filesystem if they are 
#            needed. Typically, user home directories should not be 
#            world-readable, as it would disclose file names to other 
#            users. If a subset of users need read access to one 
#            another's home directories, this can be provided using 
#            groups or ACLs.
#
# Note: This finding only requires setting user's home-directory
#       permissions to 750. However, this handler will set user's
#       home directories to mode 700
#
#################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "-----------------------------------"
diag_out "SCAP Recommendation: "
diag_out "  User's home directories should"
diag_out "  be set to mode 750 or more"
diag_out "  restrictive"
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "-----------------------------------"

