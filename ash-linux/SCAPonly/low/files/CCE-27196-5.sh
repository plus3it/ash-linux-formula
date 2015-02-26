#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID:
# - mount_option_noexec_removable_partitions
#
# Security identifiers:
# - CCE-27196-5
#
# Rule Summary: Add noexec Option to Removable Media Partitions
#
# Rule Text: The noexec mount option prevents the direct execution of 
#            binaries on the mounted filesystem. Preventing the direct 
#            execution of binaries from removable media (such as a USB 
#            key) provides a defense against malicious software that may 
#            be present on such untrusted media. Add the noexec option 
#            to the fourth column of /etc/fstab for the line which 
#            controls mounting of any removable media partitions.
#
#            Allowing users to execute binaries from removable media 
#            such as USB keys exposes the system to potential compromise.
#
#################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "-----------------------------------"
diag_out "SCAP Recommendation: "
diag_out "  Add 'noexec' options to mount"
diag_out "  definitions for removable media"
diag_out "  managed via /etc/fstab"
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "-----------------------------------"
