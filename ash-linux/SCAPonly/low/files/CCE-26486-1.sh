#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Security identifiers:
# - CCE-26486-1
#
# Rule Id: mount_option_dev_shm_nosuid
#
# Rule Summary: Set 'nosuid' option on '/dev/shm' partition
#
# Rule Text: The nosuid mount option can be used to prevent execution of 
#            setuid programs in /dev/shm. The suid/sgid permissions should 
#            not be required in these world-writable directories. Add 
#            the nosuid option to the fourth column of /etc/fstab for 
#            the line which controls mounting of /dev/shm.
#
#################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "SCAP Recommendation: "
diag_out "  Add 'nosuid' to the '/dev/shm'"
diag_out "  filesystem's mount options."
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "----------------------------------"

