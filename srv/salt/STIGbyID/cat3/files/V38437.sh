#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38437
# Finding ID:	V-38437
# Version:	RHEL-06-000526
# Finding Level:	Low
#
#     All filesystems that are required for the successful operation of the 
#     system should be explicitly listed in "/etc/fstab" by an 
#     administrator. New filesystems should not be arbitrarily introduced 
#     via the automounter. The "autofs" daemon mounts and unmounts 
#     filesystems, such as user home directories shared via NFS, on demand. 
#     In addition, autofs can be used to handle removable media, and the 
#     default configuration provides the cdrom device as "/misc/cd". 
#     However, this method of providing access to removable media is not 
#     common, so autofs can almost always be disabled if NFS is not in use. 
#     Even if NFS is required, it is almost always possible to configure 
#     filesystem mounts statically by editing "/etc/fstab" rather than 
#     relying on the automounter. 
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38437"
diag_out "  Automated file system mounting"
diag_out "  tools must not be enabled unless"
diag_out "  needed."
diag_out "----------------------------------"
