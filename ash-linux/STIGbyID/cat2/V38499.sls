# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38499
# Finding ID:	V-38499
# Version:	RHEL-06-000031
# Finding Level:	Medium
#
#     The /etc/passwd file must not contain password hashes. The hashes for 
#     all user account passwords should be stored in the file "/etc/shadow" 
#     and never in "/etc/passwd", which is readable by all users.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38499-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38499.sh
    - cwd: '/root'

cmd_V38499:
  cmd.run:
    - name: '/usr/sbin/pwconv'
