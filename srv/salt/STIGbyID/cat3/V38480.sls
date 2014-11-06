# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38480
# Finding ID:	V-38480
# Version:	RHEL-06-000054
# Finding Level:	Low
#
#     Users must be warned 7 days in advance of password expiration. 
#     Setting the password warning age enables users to make the change at 
#     a practical time.
#
############################################################

script_V38480-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38480.sh

# Super-ugly: gotta spiff later
script_V38480-helper:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38480-helper.sh
