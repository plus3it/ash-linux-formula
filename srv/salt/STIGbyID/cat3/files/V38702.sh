#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38702
# Finding ID:	V-38702
# Version:	RHEL-06-000339
# Finding Level:	Low
#
#     The FTP daemon must be configured for logging or verbose mode. To 
#     trace malicious activity facilitated by the FTP service, it must be 
#     configured to ensure that all commands sent to the ftp server are 
#     logged using the verbose vsftpd log format. The default vsftpd log
#     file is /var/log/vsftpd.log
#
#  CCI: CCI-000130
#  NIST SP 800-53 :: AU-3
#  NIST SP 800-53A :: AU-3.1
#  NIST SP 800-53 Revision 4 :: AU-3
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38702"
diag_out "  The FTP daemon must be"
diag_out "  configured for logging or"
diag_out "  verbose mode."
diag_out "----------------------------------"
