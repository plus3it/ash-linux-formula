#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38486
# Finding ID:	V-38486
# Version:	RHEL-06-000505
# Finding Level:	Medium
#
#     Operating system backup is a critical step in maintaining data
#     assurance and availability. System-level information includes
#     system-state information, operating system and application software,
#     and licenses. Backups must be consistent with organizational recovery
#     time and recovery point objectives.
#
#  CCI: CCI-000537
#  NIST SP 800-53 :: CP-9 (b)
#  NIST SP 800-53A :: CP-9.1 (v)
#  NIST SP 800-53 Revision 4 :: CP-9 (b)
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38486"
diag_out "  Ascertain if system is protected"
diag_out "  through backups of both config"
diag_out "  and other operating system data"
diag_out "----------------------------------"
