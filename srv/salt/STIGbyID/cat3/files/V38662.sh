#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38662
# Finding ID:	V-38662
# Version:	RHEL-06-000277
# Finding Level:	Low
#
#     The operating system must employ cryptographic mechanisms to prevent 
#     unauthorized disclosure of data at rest unless otherwise protected by 
#     alternative physical measures. The risk of a system's physical 
#     compromise, particularly mobile systems such as laptops, places its 
#     data at risk of compromise. Encrypting this data mitigates the risk 
#     of its loss if the system is lost.
#
#  CCI: CCI-001200
#  NIST SP 800-53 :: SC-28 (1)
#  NIST SP 800-53A :: SC-28 (1).1 (i)
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38662"
diag_out "  system must employ"
diag_out "  cryptographic mechanisms to"
diag_out "  prevent unauthorized disclosure"
diag_out "  of data at rest unless"
diag_out "  otherwise protected by"
diag_out "  alternative physical measures"
diag_out "----------------------------------"
