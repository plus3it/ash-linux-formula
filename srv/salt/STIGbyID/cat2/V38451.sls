# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38451
# Finding ID:	V-38451
# Version:	RHEL-06-000040
# Finding Level:	Medium
#
#     The /etc/passwd file must be group-owned by root. The "/etc/passwd" 
#     file contains information about the users that are configured on the 
#     system. Protection of this file is critical for system security.
#
############################################################

script_V38451-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38451.sh

file_38451:
  file.managed:
  - name: /etc/passwd
  - group: root
