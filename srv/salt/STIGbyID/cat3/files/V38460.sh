#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38460
# Finding ID:	V-38460
# Version:	RHEL-06-000515
# Finding Level:	Low
#
#     The NFS server must not have the all_squash option enabled. The 
#     "all_squash" option maps all client requests to a single anonymous 
#     uid/gid on the NFS server, negating the ability to track file access 
#     by user ID.
#
#  CCI: CCI-000764
#  NIST SP 800-53 :: IA-2
#  NIST SP 800-53A :: IA-2.1
#  NIST SP 800-53 Revision 4 :: IA-2
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38460"
diag_out "  NFS server should not use the"
diag_out "  all_squash option on exports"
diag_out "----------------------------------"
