#!/bin/sh
#
# Finding ID:	
# Version:	mount_option_nodev_nonroot_local_partitions
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#	The nodev mount option prevents files from being
#	interpreted as character or block devices. The only
#	legitimate location for device files is the /dev
#	directory located on the root partition. The only
#	exception to this is chroot jails, for which it is not
#	advised to set nodev on these filesystems.
#
# CCI-xxxxxx CCI-xxxxxx
#    NIST SP 800-53 Revision 4 :: CM-7
#    NIST SP 800-53 Revision 4 :: MP-2
#    CIS RHEL 7 Benchmark 1.1.0 :: 1.1.11
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "-------------------------------------------"
diag_out "STIG Finding ID:"
diag_out "mount_option_nodev_nonroot_local_partitions"
diag_out "   Set nodev option on all local, non-root"
diag_out "   filesystems."
diag_out "-------------------------------------------"
