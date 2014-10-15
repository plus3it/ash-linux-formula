# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38448
# Finding ID:	V-38448
# Version:	RHEL-06-000037
# Finding Level:	Medium
#
#     The /etc/gshadow file must be group-owned by root. The "/etc/gshadow" 
#     file contains group password hashes. Protection of this file is 
#     critical for system security.
#
############################################################

script_V38448-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38448.sh

file_38448:
  file.managed:
  - name: /etc/gshadow
  - group: root
