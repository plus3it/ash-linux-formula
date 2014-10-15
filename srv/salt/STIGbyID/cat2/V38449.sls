# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38449
# Finding ID:	V-38449
# Version:	RHEL-06-000038
# Finding Level:	Medium
#
#     The /etc/gshadow file must have mode 0000. The /etc/gshadow file 
#     contains group password hashes. Protection of this file is critical 
#     for system security.
#
############################################################

script_V38449-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38449.sh

file_38449:
  file.managed:
  - name: /etc/gshadow
  - mode: 0000
