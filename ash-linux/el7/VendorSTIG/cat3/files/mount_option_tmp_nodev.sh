#!/bin/bash
# Finding ID:	
# Version:	mount_option_tmp_nodev
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#       The nodev mount option can be used to prevent device
#       files from being created in /tmp. Legitimate character
#       and block devices should not exist within temporary
#       directories like /tmp. Add the nodev option to the
#       fourth column of /etc/fstab for the line which controls
#       mounting of /tmp.
#
# CCI-xxxxxx CCI-xxxxxx
#    NIST SP 800-53 Revision 4 :: CM-7
#    NIST SP 800-53 Revision 4 :: MP-2
#    CIS RHEL 7 Benchmark 1.1.0 :: 1.1.2
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: mount_option_tmp_nodev"
diag_out "   The only legitimate location for"
diag_out "   device files is the /dev directory"
diag_out "   located on the root partition."
diag_out "----------------------------------------"
