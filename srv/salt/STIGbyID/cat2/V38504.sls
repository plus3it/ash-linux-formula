# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38504
# Finding ID:	V-38504
# Version:	RHEL-06-000035
# Finding Level:	Medium
#
#     The /etc/shadow file must have mode 0000. The "/etc/shadow" file 
#     contains the list of local system accounts and stores password 
#     hashes. Protection of this file is critical for system security. 
#     Failure to give ownership of this file to root ...
#
############################################################

script_V38504-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38504.sh

file_V38504:
  file.managed:
  - name: /etc/shadow
  - mode: 0000
