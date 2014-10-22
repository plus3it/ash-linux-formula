# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38593
# Finding ID:	V-38593
# Version:	RHEL-06-000073
# Finding Level:	Medium
#
#     The Department of Defense (DoD) login banner must be displayed 
#     immediately prior to, or as part of, console login prompts. An 
#     appropriate warning message reinforces policy awareness during the 
#     logon process and facilitates possible legal action against attackers.
#
############################################################

script_V38593-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38593.sh

file_V38593-etcIssue:
  file.managed:
  - name: '/etc/issue'
  - source: salt://STIGbyID/cat2/files/issue.txt
