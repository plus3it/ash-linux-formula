#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38438
# Finding ID:	V-38438
# Version:	RHEL-06-000525
# Finding Level:	Low
#
#     Each process on the system carries an "auditable" flag which 
#     indicates whether its activities can be audited. Although "auditd" 
#     takes care of enabling this for all processes which launch after it 
#     does, adding the kernel argument ensures it is set for every process 
#     during boot. 
#
#  CCI: CCI-000169
#  NIST SP 800-53 :: AU-12 a
#  NIST SP 800-53A :: AU-12.1 (ii)
#  NIST SP 800-53 Revision 4 :: AU-12 a
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38438"
diag_out "  Auditing must be enabled at"
diag_out "  kernel load-time"
diag_out "----------------------------------"
