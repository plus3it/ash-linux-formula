# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38482
# Finding ID:	V-38482
# Version:	RHEL-06-000056
# Finding Level:	Low
#
#     The system must require passwords to contain at least one numeric 
#     character. Requiring digits makes password guessing attacks more 
#     difficult by ensuring a larger search space.
#
############################################################

script_V38480-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38480.sh

