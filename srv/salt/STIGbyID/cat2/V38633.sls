# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38633
# Finding ID:	V-38633
# Version:	RHEL-06-000160
# Finding Level:	Medium
#
#     The system must set a maximum audit log file size. The total storage 
#     for audit log files must be large enough to retain log information 
#     over the period required. This is a function of the maximum log file 
#     size and the number of logs retained.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38633-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38633.sh

cmd_V38633-NotImplemented:
  cmd.run:
  - name: 'echo "NOT YET IMPLEMENTED"'

