#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Security identifiers:
# - CCE-26762-5
#
# Rule Summary: Set 'nosuid' option on '/tmp' partition
#
# Rule Text: The nosuid mount option can be used to prevent execution of 
#            setuid programs in /tmp. The suid/sgid permissions should 
#            not be required in these world-writable directories. Add 
#            the nosuid option to the fourth column of /etc/fstab for 
#            the line which controls mounting of /tmp.
#
#################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "SCAP Recommendation: "
diag_out "  Add 'nosuid' to the '/tmp'"
diag_out "  filesystem's mount options."
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "----------------------------------"

