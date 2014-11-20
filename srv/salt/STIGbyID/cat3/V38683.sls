# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38683
# Finding ID:	V-38683
# Version:	RHEL-06-000296
# Finding Level:	Low
#
#     All accounts on the system must have unique user or account names 
#     Unique usernames allow for accountability on the system.
#
#  CCI: CCI-000804
#  NIST SP 800-53 :: IA-8
#  NIST SP 800-53A :: IA-8.1
#  NIST SP 800-53 Revision 4 :: IA-8
#
############################################################

script_V38683-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38683.sh

notify_V38683-notImp:
  cmd.run:
  - name: "NOT YET IMPLEMENTED"

