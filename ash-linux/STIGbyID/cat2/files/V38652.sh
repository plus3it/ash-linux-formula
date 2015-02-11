#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38652
# Finding ID:	V-38652
# Version:	RHEL-06-000269
# Finding Level:	Medium
#
#     Remote file systems must be mounted with the nodev option. Legitimate 
#     device files should only exist in the /dev directory. NFS mounts 
#     should not present device files to users.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38652"
diag_out "  Remote file systems must be"
diag_out "  mounted with the nodev option"
diag_out "----------------------------------"

