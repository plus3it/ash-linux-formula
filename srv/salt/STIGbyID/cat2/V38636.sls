# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38636
# Finding ID:	V-38636
# Version:	RHEL-06-000159
# Finding Level:	Medium
#
#     The system must retain enough rotated audit logs to cover the 
#     required log retention period. The total storage for audit log files 
#     must be large enough to retain log information over the period 
#     required. This is a function of the maximum log file size and the 
#     number of logs retained.
#
############################################################

script_V38636-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38636.sh

cmd_V38636-NotImplemented:
  cmd.run:
  - name: 'echo "NOT YET IMPLEMENTED"'
