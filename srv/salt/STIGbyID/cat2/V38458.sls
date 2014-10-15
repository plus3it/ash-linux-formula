# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38458
# Finding ID:	V-38458
# Version:	RHEL-06-000042
# Finding Level:	Medium
#
#     The /etc/group file must be owned by root. The "/etc/group" file 
#     contains information regarding groups that are configured on the 
#     system. Protection of this file is important for system security.
#
############################################################

script_V38458-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38458.sh

file_38458:
  file.managed:
  - name: /etc/group
  - user: root
