# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38459
# Finding ID:	V-38459
# Version:	RHEL-06-000043
# Finding Level:	Medium
#
#     The /etc/group file must be group-owned by root. The "/etc/group" 
#     file contains information regarding groups that are configured on the 
#     system. Protection of this file is important for system security.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38459-describe:
  cmd.script:
    - source: salt://STIGbyID/cat2/files/V38459.sh

file_V38459:
  file.managed:
    - name: /etc/group
    - group: root
