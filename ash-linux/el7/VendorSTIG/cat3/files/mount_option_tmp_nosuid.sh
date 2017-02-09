#!/bin/bash
# Finding ID:	
# Version:	mount_option_tmp_suid
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#       The nosuid mount option can be used to prevent
#       execution of setuid programs in /tmp. The SUID and
#       SGID permissions should not be required in these
#       world-writable directories. Add the nosuid option to
#       the fourth column of /etc/fstab for the line which
#       controls mounting of /tmp.
#
# CCI-xxxxxx CCI-xxxxxx
#    NIST SP 800-53 Revision 4 :: CM-7
#    NIST SP 800-53 Revision 4 :: MP-2
#    CIS RHEL 7 Benchmark 1.1.0 :: 1.1.3
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: mount_option_tmp_nosuid"
diag_out "   The presence of SUID and SGID"
diag_out "   executables should be tightly"
diag_out "   controlled. Users should not be able"
diag_out "   to execute SUID or SGID binaries"
diag_out "   from temporary storage partitions."
diag_out "----------------------------------------"
