#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38697
# Finding ID:	V-38697
# Version:	RHEL-06-000336
# Finding Level:	Low
#
#     Failing to set the sticky bit on public directories allows 
#     unauthorized users to delete files in the directory structure. The 
#     only authorized public directories are those temporary directories 
#     supplied with the system, or those designed to be temporary file 
#     repositories. The setting is normally reserved for directories used 
#     by the system, and by users for temporary file storage - such as /tmp 
#     - and for directories requiring global read/write access. 
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
diag_out "STIG Finding ID: V-38697"
diag_out "  The sticky bit must be set on"
diag_out "  all public directories."
diag_out "----------------------------------"
