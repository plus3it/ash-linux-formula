# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38573
# Finding ID:	V-38573
# Version:	RHEL-06-000061
# Finding Level:	Medium
#
#     The system must disable accounts after three consecutive unsuccessful 
#     login attempts. Locking out user accounts after a number of incorrect 
#     attempts prevents direct password guessing attacks.
#
############################################################

script_V38573-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38573.sh

cmd_V38573-NotImplemented:
  cmd.run:
  - name: 'echo "NOT YET IMPLEMENTED"'

