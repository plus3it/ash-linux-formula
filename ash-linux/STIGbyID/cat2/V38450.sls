# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38450
# Finding ID:	V-38450
# Version:	RHEL-06-000039
# Finding Level:	Medium
#
#     The /etc/passwd file must be owned by root. The "/etc/passwd" file 
#     contains information about the users that are configured on the 
#     system. Protection of this file is critical for system security.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38450-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38450.sh

file_38450:
  file.managed:
  - name: /etc/passwd
  - user: root
