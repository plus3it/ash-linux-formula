#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38530
# Finding ID:	V-38530
# Version:	RHEL-06-000173
# Finding Level:	Low
#
#     The audit system must be configured to audit all attempts to alter 
#     system time through /etc/localtime. Arbitrary changes to the system 
#     time can be used to obfuscate nefarious activities in log files, as 
#     well as to confuse network services that are highly dependent upon an 
#     accurate system time (such as sshd). All changes to the system time 
#     should be audited. 
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

diag_out "-----------------------------------"
diag_out "STIG Finding ID: V-38530"
diag_out "  audit system must be configured"
diag_out "  to audit all attempts to alter"
diag_out "  system time through"
diag_out "  /etc/localtime"
diag_out "-----------------------------------"
