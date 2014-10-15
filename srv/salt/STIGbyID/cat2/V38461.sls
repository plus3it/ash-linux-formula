# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38461
# Finding ID:	V-38461
# Version:	RHEL-06-000044
# Finding Level:	Medium
#
#     The /etc/group file must have mode 0644 or less permissive. The 
#     "/etc/group" file contains information regarding groups that are 
#     configured on the system. Protection of this file is important for 
#     system security.
#
############################################################

script_V38461-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38461.sh

file_V38461:
  file.managed:
  - name: /etc/group
  - mode: 0644
