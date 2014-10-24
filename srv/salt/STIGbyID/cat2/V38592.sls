# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38592
# Finding ID:	V-38592
# Version:	RHEL-06-000356
# Finding Level:	Medium
#
#     The system must require administrator action to unlock an account 
#     locked by excessive failed login attempts. Locking out user accounts 
#     after a number of incorrect attempts prevents direct password 
#     guessing attacks. Ensuring that an administrator is involved in 
#     unlocking locked accounts draws appropriate ...
#
############################################################

script_V38592-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38592.sh

cmd_V38592-NotImplemented:
  cmd.run:
  - name: 'echo "NOT YET IMPLEMENTED"'

